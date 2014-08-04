#include <stdio.h>
#include "pin.H"
#include "winapi.h"
#include "common.h"

FILE * trace;

#ifndef TRACE_EN
    #define TRACE_EN 0
#endif

/*
 * The ID of the buffer
 */
BUFFER_ID bufId;

#define NUM_BUF_PAGES 1024

typedef struct {
     PVOID ExceptionList;
     PVOID StackBase;
     PVOID StackLimit;
     PVOID SubSystemTib;
     union
     {
          PVOID FiberData;
          ULONG Version;
     };
     PVOID ArbitraryUserPointer;
     PVOID Self;
} NT_TIB;


PROCESS_ENV * pe;

VOID RecordMemRead(VOID * ip, VOID * addr) {
    fprintf(trace,"%p: R %p\n", ip, addr);
}


int DLL_getDllIndex(THREAD_ENV	* current_t, ADDRINT ip) {
	for(int i = 0; i < current_t->dll_count; i++) {
		if(IS_WITHIN_RANGE(ip, (current_t->dll_envs[i]->code_range))) {
			return i;
		}
	}
	return current_t->dll_count;
}

#define WRITES_DLL_WHITELIST_SCHEME			0x01
#define WRITES_DLL_BLACKLIST_SCHEME			0x02
#define WRITES_DLL_INCLUDE_SCHEME			(WRITES_DLL_BLACKLIST_SCHEME)
#define WRITES_DLL_WHITELIST				"kernel32.dll", NULL
#define WRITES_DLL_BLACKLIST				"USER32.dll", "ntdll.dll", NULL	

bool DLL_isInWriteBlackList(char *dll_name) {
	static char* dll_blacklist[] = { WRITES_DLL_BLACKLIST };
	int i;
	for(i=0;dll_blacklist[i]!=NULL;i++) {
		if(!strncmp((char*)dll_name, dll_blacklist[i], strlen(dll_blacklist[i]))) {
			//DbgPrint("[DLL] Ignoring writes from DLL %s\n", dll_name);
			return TRUE;
		}
	}
	return FALSE;
}

bool DLL_isInWriteWhiteList(char *dll_name) {
	static char* dll_whitelist[] = { WRITES_DLL_WHITELIST };
	int i;
	for(i=0;dll_whitelist[i]!=NULL;i++) {
		if(!strncmp((char*)dll_name, dll_whitelist[i], strlen(dll_whitelist[i]))) {
			return TRUE;
		}
	}
	return FALSE;
}

VOID RecordMemWrite(INT32 th_id, INT32 mw, VOID * ip, VOID * addr) {

	THREAD_ENV * current_t;
	DLL_ENV * current_d;

    if(pe->lookup_table[th_id] == -1) {
        pe->thread_envs[pe->thread_count] = (THREAD_ENV *) malloc(sizeof(THREAD_ENV));
        pe->lookup_table[th_id] = pe->thread_count;
        pe->thread_count++;

		fprintf(trace, "[*] New thread %d (total=%d) detected (IP=%p, MEM=%p)\n", th_id, pe->thread_count, ip, addr);

		UINT64 value;
		UINT64 *teb64_address;
        __asm {
            mov EAX, GS:[0x30]
            mov teb64_address, EAX
        }

		PIN_SafeCopy (&value, teb64_address+0x100, sizeof(UINT64));
		fprintf(trace, "[!]   TEB64 address *(%016X): %016X\n", teb64_address, *teb64_address);
		fprintf(trace, "[!]     WOW64 flag = %value\n");
		if(value == NULL) {
			
		}
		
		UINT32 stack_base;
		UINT32 stack_limit;
		UINT32 *teb32_address = (UINT32 *) teb64_address + (0x2000/4);

		// REMEMBER POINTER ARITHMETIC
		PIN_SafeCopy (&stack_base, teb32_address+1, sizeof(UINT32));
		PIN_SafeCopy (&stack_limit, teb32_address+2, sizeof(UINT32));	
		
		fprintf(trace, "[!]   TEB32 address: %p\n", teb32_address);
		fprintf(trace, "[!]     StackBase:	%p\n", stack_base);
		fprintf(trace, "[!]     StackLimit:	%p\n", stack_limit);

        pe->thread_envs[pe->lookup_table[th_id]]->stack_range[0] = (ADDRINT) stack_limit;
		pe->thread_envs[pe->lookup_table[th_id]]->stack_range[1] = (ADDRINT) stack_base;

		set_range(trace, pe->thread_envs[pe->lookup_table[th_id]]->data_range, ".data");
		set_range(trace, pe->thread_envs[pe->lookup_table[th_id]]->code_range, ".text");
		
		pe_fill_dlls(trace, pe->thread_envs[pe->lookup_table[th_id]]);

    }

	current_t = pe->thread_envs[pe->lookup_table[th_id]];

	pe->bytecounter += mw;
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
		int dll_index = DLL_getDllIndex(pe->thread_envs[pe->lookup_table[th_id]], (ADDRINT) ip);
		if(dll_index == pe->thread_envs[pe->lookup_table[th_id]]->dll_count) {
			fprintf(trace, "[!] Code base unknown for instruction %p\n", ip);
		} else {
			current_d = pe->thread_envs[pe->lookup_table[th_id]]->dll_envs[dll_index];
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
						current_d->slstack_counter				+= mw;
						current_t->global_slstack_counter		+= mw;
					}
				} else {
					current_d->heap_counter					+= mw;
					current_t->global_heap_counter			+= mw;
				}
			}
		}	
	}
}

struct MEMREF {
    ADDRINT     pc;
    ADDRINT     ea;
    UINT32      size;
    BOOL        read;
	UINT32		tid;

};

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


VOID Instruction(INS ins, VOID *v) {
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsWritten(ins, memOp) ) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_THREAD_ID,
                IARG_MEMORYWRITE_SIZE,
                IARG_INST_PTR,  
                IARG_MEMORYOP_EA, memOp,
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


VOID * BufferFull(BUFFER_ID id, THREADID tid, const CONTEXT *ctxt, VOID *buf, UINT64 numElements, VOID *v) {
    /*
    This code will work - but it is very slow, so for testing purposes we run with the Knob turned off
    */

	return buf;
	/*
    if (KnobDoWriteToOutputFile)
    {
        PIN_GetLock(&fileLock, 1);

        struct MEMREF * reference=(struct MEMREF*)buf;

        for(UINT64 i=0; i<numElements; i++, reference++)
        {
            if (reference->ea != 0)
                ofile << tid << "   "  << reference->pc << "   " << reference->ea << endl;
        }
        PIN_ReleaseLock(&fileLock);
    }

    return buf;
	*/
}

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    // There is a new MLOG for every thread.  Opens the output file.
    //MLOG * mlog = new MLOG(tid);

    // A thread will need to look up its MLOG, so save pointer in TLS
    //PIN_SetThreadData(mlog_key, mlog, tid);
	fprintf(trace,"[*] Thread (%p) started\n", tid); 
}


/* ===================================================================== */
/* Main */
/* ===================================================================== */
int main(int argc, char *argv[]) {


	//DivideByZero();
	trace = fopen("C:\\Users\\Stefano\\Desktop\\mepropin\\pinatrace.out", "w");
    //trace = fopen("C:\\temp\\pinatrace.out", "w");

	if (trace == NULL) return 0;
    if (PIN_Init(argc, argv)) return Usage();

	/* Playing with PE */
    pe = (PROCESS_ENV *) malloc(sizeof(pe));
    memset(pe->lookup_table, -1, sizeof(INT32) * 2048);
    pe->thread_count = 0;
    sprintf(pe->name, "TEST.exe", sizeof("TEST.exe"));




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
