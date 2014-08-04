#include <stdio.h>
#include "pin.H"
#include "winapi.h"
#include "common.h"

FILE * trace;
PROCESS_ENV * pe;

#ifndef TRACE_EN
	#define TRACE_EN 0
#endif

VOID TestCall(INT32 th_id, const CONTEXT * ctx, UINT32 mw, VOID *ip, void *addr) {
	ADDRINT esp = PIN_GetContextReg(ctx, REG_ESP);
	fprintf(trace, "[*] %p\n", esp);
}

ADDRINT AffectStack(INT32 th_id, VOID * addr, UINT32 esp_value) {
	
	if(pe->lookup_table[th_id] == -1) {
		return 1;
	}

	// FIX ME - Check ESP values
#if (WRITES_STACK_SCHEME & WRITES_STACK_ALL_SCHEME)
	if (IS_WITHIN_RANGE((ADDRINT) addr, pe->thread_envs[pe->lookup_table[th_id]]->stack_range)) {
#else if (WRITES_STACK_SCHEME & WRITES_STACK_LLS_SCHEME)
	if (esp_value < pe->thread_envs[pe->lookup_table[th_id]]->esp_min) {
#endif
		return 0;
	}
	return 1;
}

VOID RecordMemWrite(INT32 th_id, const CONTEXT * ctx, UINT32 mw, VOID * ip, VOID * addr) {
	ADDRINT esp = PIN_GetContextReg(ctx, REG_ESP);
	THREAD_ENV * current_t;
	DLL_ENV * current_d;
	pe->bytecounter += mw;

	if(pe->lookup_table[th_id] == -1) {
		pe->thread_envs[pe->thread_count] = (THREAD_ENV *) malloc(sizeof(THREAD_ENV));
		pe->lookup_table[th_id] = pe->thread_count;
		pe->thread_count++;

		UINT64 value;
		UINT64 *teb64_address;
		__asm {
			mov EAX, GS:[0x30]
			mov teb64_address, EAX
		}

		PIN_SafeCopy (&value, teb64_address+0x100, sizeof(UINT64));	
		UINT32 stack_base;
		UINT32 stack_limit;
		UINT32 *teb32_address = (UINT32 *) teb64_address + (0x2000/4);

		// REMEMBER POINTER ARITHMETIC
		PIN_SafeCopy (&stack_base, teb32_address+1, sizeof(UINT32));
		PIN_SafeCopy (&stack_limit, teb32_address+2, sizeof(UINT32));

		fprintf(trace, "[*] New thread %d (total=%d) detected (IP=%p, MEM=%p)\n", th_id, pe->thread_count, ip, addr);
		fprintf(trace, "[!]	 TEB64 address *(%016X): %016X\n", teb64_address, *teb64_address);
		fprintf(trace, "[!]		 WOW64 flag = %p\n", value);
		fprintf(trace, "[!]	 TEB32 address: %p\n", teb32_address);
		fprintf(trace, "[!]		 StackBase:	%p\n", stack_base);
		fprintf(trace, "[!]		 StackLimit:	%p\n", stack_limit);

		pe->thread_envs[pe->lookup_table[th_id]]->stack_range[0] = (ADDRINT) stack_limit;
		pe->thread_envs[pe->lookup_table[th_id]]->stack_range[1] = (ADDRINT) stack_base;

		// FIXME: Alternative version to get stack top and stack bottom 
		/*
		ADDRINT teb = PIN_GetContextReg(ctx,REG_SEG_FS_BASE);
		ADDRINT stackTop;
		ADDRINT stackBottom;
		PIN_SafeCopy(&stackTop,((int*)teb+1),4);
		PIN_SafeCopy(&stackBottom,((int*)teb+2),4);
		*/

		set_range(trace, pe->thread_envs[pe->lookup_table[th_id]]->data_range, ".data");
		set_range(trace, pe->thread_envs[pe->lookup_table[th_id]]->code_range, ".text");

		pe->thread_envs[pe->lookup_table[th_id]]->esp_max = 0;
		pe->thread_envs[pe->lookup_table[th_id]]->esp_min = esp;
		
		pe_fill_dlls(trace, pe->thread_envs[pe->lookup_table[th_id]]);

	} else {
		if(esp > pe->thread_envs[pe->lookup_table[th_id]]->esp_min) {
			pe->thread_envs[pe->lookup_table[th_id]]->esp_min = 0;
			if(esp > pe->thread_envs[pe->lookup_table[th_id]]->esp_max) {
				pe->thread_envs[pe->lookup_table[th_id]]->esp_max = esp;
			}
		} else {
			pe->thread_envs[pe->lookup_table[th_id]]->esp_min = esp;
		}
	}

	current_t = pe->thread_envs[pe->lookup_table[th_id]];
	if(IS_WITHIN_RANGE((ADDRINT) ip, current_t->code_range)) {
		if(IS_WITHIN_RANGE((ADDRINT) addr, current_t->data_range)) {
			current_t->data_counter += mw;
			current_t->global_data_counter += mw;
		} else if (IS_WITHIN_RANGE((ADDRINT) addr, current_t->stack_range)) {
			current_t->stack_counter += mw;
			current_t->global_stack_counter += mw;
			if( (ADDRINT) ip >= current_t->esp_max) {
				current_t->slstack_counter += mw;
				current_t->global_slstack_counter += mw;
			}
		} else {
			current_t->heap_counter += mw;
			current_t->global_heap_counter += mw;
		}
	} else {
		int dll_index = DLL_getDllIndex(current_t, (ADDRINT) ip);
		if(dll_index == current_t->dll_count) {
			fprintf(trace, "[?] Code base unknown for address %p\n", ip);
			dll_index = pe_fill_dll(trace, current_t, (ADDRINT) ip);
			// We could recover BUT instead we ABORT since we are debugging
			/*
			if(dll_index == current_t->dll_count) {
				fprintf(trace, "[!] Code base STILL unknown for address %p\n", ip);
				dll_index = pe_create_dll(trace, current_t, (ADDRINT) ip);
			}
			*/
			ASSERT(dll_index != current_t->dll_count, "[!] Code base STILL unknown!! Abort!!");
			fprintf(trace, "[!] Code base now known for address %p\n", ip);
		}

		current_d = current_t->dll_envs[dll_index];
#if (WRITES_DLL_INCLUDE_SCHEME & WRITES_DLL_BLACKLIST_SCHEME)		
		if(!DLL_isInWriteBlackList(current_d->name)) {
#else if (WRITES_DLL_INCLUDE_SCHEME & WRITES_DLL_WHITELIST_SCHEME)
		if(DLL_isInWriteWhiteList(current_d->name)) {
#endif
			if(IS_WITHIN_RANGE((ADDRINT) ip, current_t->data_range) || 
				IS_WITHIN_RANGE((ADDRINT) ip, current_d->data_range)) {
				current_d->data_counter					+= mw;
				current_t->global_data_counter			+= mw;
			} else if(IS_WITHIN_RANGE((ADDRINT) ip, current_t->stack_range)) {
				current_d->stack_counter				+= mw;
				current_t->global_stack_counter			+= mw;
				if((ADDRINT) ip >= current_t->esp_max) {
					current_d->slstack_counter			+= mw;
					current_t->global_slstack_counter	+= mw;
				}
			} else {
				current_d->heap_counter					+= mw;
				current_t->global_heap_counter			+= mw;
			}
		}	
	}
}

VOID Instruction(INS ins, VOID *v) {
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
		if (INS_MemoryOperandIsWritten(ins, memOp) ) {
			// FIRST VERSIN (USELESS MEMORYUP_EA) 
			/*
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
				IARG_THREAD_ID,
				IARG_CONTEXT,
				IARG_MEMORYWRITE_SIZE,
				IARG_INST_PTR,	
				IARG_MEMORYOP_EA, memOp,
				IARG_END);
			*/
			
			// SECOND VERSION (SLOW) 
			/*
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, 
				IARG_THREAD_ID, 
				IARG_CONTEXT,
				IARG_MEMORYWRITE_SIZE,
				IARG_INST_PTR,
				IARG_MEMORYWRITE_EA,
				IARG_END);
			*/

			// THIRD VERSION (READY TO BE THE FASTEST
			INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)AffectStack, 
				IARG_THREAD_ID, 
				IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, REG_STACK_PTR,
				IARG_END);

			INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, 
				IARG_THREAD_ID, 
				IARG_CONTEXT,
				IARG_MEMORYWRITE_SIZE,
				IARG_INST_PTR,
				IARG_MEMORYWRITE_EA,
				IARG_END);
		}
	}
}

VOID Fini(INT32 code, VOID *v) {
	print_stats(trace, pe);
	fprintf(trace, "#eof\n");
	fclose(trace);
}

INT32 Usage() {
	PIN_ERROR( "This Pintool prints a trace of memory addresses\n"
		+ KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

#if TRACE_EN

#define NUM_BUF_PAGES 	1024

BUFFER_ID bufId;

struct MEMREF {
	ADDRINT		pc;
	ADDRINT		ea;
	UINT32		size;
	BOOL		read;
	UINT32		tid;
};

VOID * BufferFull(BUFFER_ID id, THREADID tid, const CONTEXT *ctxt, VOID *buf, UINT64 numElements, VOID *v) {
	/*
	if (KnobDoWriteToOutputFile) {
		PIN_GetLock(&fileLock, 1);
		struct MEMREF * reference=(struct MEMREF*)buf;
		for(UINT64 i=0; i<numElements; i++, reference++) {
			if (reference->ea != 0) {
				ofile << tid << "	 "	<< reference->pc << "	 " << reference->ea << endl;
			}
		}
		PIN_ReleaseLock(&fileLock);
	}
	*/
	return buf;
}

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
	// There is a new MLOG for every thread.	Opens the output file.
	//MLOG * mlog = new MLOG(tid);
	//PIN_SetThreadData(mlog_key, mlog, tid);
	fprintf(trace,"[*] Thread (%p) started\n", tid); 
}

VOID Trace(TRACE trace, VOID *v) {
	for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl=BBL_Next(bbl)) {
		for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins=INS_Next(ins)) {
			UINT32 memoryOperands = INS_MemoryOperandCount(ins);
			for (UINT32 memOp = 0; memOp < memoryOperands; memOp++) {
				UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
				if (INS_MemoryOperandIsWritten(ins, memOp)) {
					INS_InsertFillBuffer(ins, IPOINT_BEFORE, bufId,
						IARG_INST_PTR, offsetof(struct MEMREF, pc),
						IARG_MEMORYOP_EA, memOp, offsetof(struct MEMREF, ea),
						IARG_UINT32, refSize, offsetof(struct MEMREF, size), 
						IARG_BOOL, FALSE, offsetof(struct MEMREF, read),
						IARG_THREAD_ID, offsetof(struct MEMREF, tid), 
						IARG_END);
				}
			}
		}
	}
}

#endif

/* ===================================================================== */
/* Main */
/* ===================================================================== */
int main(int argc, char *argv[]) {

	trace = fopen(MEPRO_LOG, "w");
	if (trace == NULL) return 0;
	if (PIN_Init(argc, argv)) return Usage();

	pe = (PROCESS_ENV *) malloc(sizeof(pe));
	memset(pe->lookup_table, -1, sizeof(INT32) * 2048);
	pe->thread_count = 0;

	// FIXME: verify this voodoo code
	char * name;
	int pid;
	for(int i = 0; i < argc; i++) {
		if(strcmp(argv[i], "-pid") == 0) {
			int pid = atoi(argv[i+1]);
			get_process_name(&name, pid);
			break;
		}
		if(strcmp(argv[i], "--") == 0) {
			char *pfile;
			pfile = argv[i+1] + strlen(argv[i+1]);
			for (; pfile > argv[i+1]; pfile--) {
				if ((*pfile == '\\') || (*pfile == '/')) {
					pfile++;
					break;
				}
			}
			name = (char *) malloc(strlen(pfile) + 1);
			strcpy(name, pfile);
			name[strlen(pfile)] = '\0';
		}
		
	}
	fprintf(trace, "[*] Process name: %s\n", name);
	strcpy(pe->name, name);
	//sprintf(pe->name, "TEST.exe", sizeof("TEST.exe"));

#if TRACE_EN
	fprintf(trace,"[*] Instrumentation TRACE MODE\n");
	bufId = PIN_DefineTraceBuffer(sizeof(struct MEMREF), NUM_BUF_PAGES, BufferFull, 0);
	TRACE_AddInstrumentFunction(Trace, 0);
	PIN_AddThreadStartFunction(ThreadStart, 0);
#else
	fprintf(trace,"[*] Instrumentation INS MODE\n");
	INS_AddInstrumentFunction(Instruction, 0);
#endif

	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();
	return 0;
}
