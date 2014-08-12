//#include <stdio.h>
/*
namespace WINDOWS
{
#include <windows.h>
	//using namespace WINDOWS;
//#include <cstring>
}
*/
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include "pin.H"
#include "winapi.h"
#include "common.h"

#include <stdio.h>

using namespace std;


FILE * trace;
PROCESS_ENV * pe;

PROCESS_ENV ** attached_processes;

#ifndef TRACE_EN
	#define TRACE_EN 0
#endif

//using boost::interprocess;

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
 
inline VOID update_pcounters(PROCESS_ENV * current_p, UINT64 mw) {
	ADD(pe->bytecounter, mw);
}

inline VOID update_tcounters(THREAD_ENV * current_t, VOID * addr, VOID * ip, UINT64 mw) {
	if(IS_WITHIN_RANGE((ADDRINT) addr, current_t->data_range)) {
		current_t->data_counter = mw;
		current_t->global_data_counter = mw;
	} else if (IS_WITHIN_RANGE((ADDRINT) addr, current_t->stack_range)) {
		current_t->stack_counter = mw;
		current_t->global_stack_counter = mw;
		if( (ADDRINT) ip >= current_t->esp_max) {
			current_t->slstack_counter = mw;
			current_t->global_slstack_counter = mw;
		}
	} else {
		current_t->heap_counter = mw;
		current_t->global_heap_counter = mw;
	}
}

inline VOID update_dcounters(THREAD_ENV * current_t, DLL_ENV * current_d, VOID * ip, UINT64 mw) {
	if(IS_MONITORED(current_d->name)) {
		if(IS_WITHIN_RANGE((ADDRINT) ip, current_t->data_range) || 
			IS_WITHIN_RANGE((ADDRINT) ip, current_d->data_range)) {
			current_d->data_counter = mw;
			current_t->global_data_counter = mw;
		} else if(IS_WITHIN_RANGE((ADDRINT) ip, current_t->stack_range)) {
			current_d->stack_counter = mw;
			current_t->global_stack_counter = mw;
			if((ADDRINT) ip >= current_t->esp_max) {
				current_d->slstack_counter = mw;
				current_t->global_slstack_counter = mw;
			}
		} else {
			current_d->heap_counter = mw;
			current_t->global_heap_counter = mw;
		}
	}
}

inline VOID update_tesp(THREAD_ENV * current_t, ADDRINT esp) {
	if(esp > current_t->esp_min) {
		current_t->esp_min = 0;
		if(esp > current_t->esp_max) {
			current_t->esp_max = esp;
		}
	} else {
		current_t->esp_min = esp;
	}
}
		

// We are updating the info of a single thread. No race here
// Since we add stuff only, no race even when another process access the structure
inline int get_dll(THREAD_ENV * current_t, VOID * ip) {
	int dll_index = DLL_getDllIndex(current_t, (ADDRINT) ip);
	if(dll_index == current_t->dll_count) {
		fprintf(trace, "[?] Code base unknown for address %p\n", ip);
		dll_index = pe_fill_dll(trace, current_t, (ADDRINT) ip);
#if ADD_UNKNOWN_DLLS
		if(dll_index == current_t->dll_count) {
			fprintf(trace, "[!] Code base STILL unknown for address %p\n", ip);
			dll_index = pe_create_dll(trace, current_t, (ADDRINT) ip);
		}
#endif
		if(dll_index == -1) {
			dll_index = pe_create_dll(trace, current_t, (ADDRINT) ip);
		}
		
		//ASSERT(dll_index != current_t->dll_count, "[!] Code base STILL unknown!! Abort!!");
		//fprintf(trace, "[!] Code base now known for address %p\n", ip);
	}
	return dll_index;
}

VOID RecordMemWrite(INT32 th_id, const CONTEXT * ctx, UINT32 mw, VOID * ip, VOID * addr) {

	ADDRINT esp = PIN_GetContextReg(ctx, REG_ESP);
	THREAD_ENV * current_t;
	
	if(pe->lookup_table[th_id] == -1) {
		UINT64 value;
		UINT32 stack_base;
		UINT32 stack_limit;
		UINT32 *teb32_address;
		UINT64 *teb64_address;
		__asm {
			mov EAX, GS:[0x30]
			mov teb64_address, EAX
		}

		PIN_SafeCopy (&value, teb64_address+0x100, sizeof(UINT64));	
		teb32_address = (UINT32 *) teb64_address + (0x2000/4);

		PIN_SafeCopy (&stack_base, teb32_address+1, sizeof(UINT32));
		PIN_SafeCopy (&stack_limit, teb32_address+2, sizeof(UINT32));

		fprintf(trace, "[*] New thread %d detected (IP=%p, MEM=%p)\n", th_id, ip, addr);
		fprintf(trace, "[!]	 TEB64 address *(%016X): %016X\n", teb64_address, *teb64_address);
		fprintf(trace, "[!]		 WOW64 flag = %p\n", value);
		fprintf(trace, "[!]	 TEB32 address: %p\n", teb32_address);
		fprintf(trace, "[!]		 StackBase:	%p\n", stack_base);
		fprintf(trace, "[!]		 StackLimit:	%p\n", stack_limit);

		current_t = (THREAD_ENV *) malloc(sizeof(THREAD_ENV));
		current_t->stack_range[0] = (ADDRINT) stack_limit;
		current_t->stack_range[1] = (ADDRINT) stack_base;

		set_range(trace, current_t->data_range, ".data");
		set_range(trace, current_t->code_range, ".text");

		current_t->esp_max = 0;
		current_t->esp_min = esp;
		
		pe_fill_dlls(trace, current_t);

#if PROTECT_FROM_RACE
		pe->lookup_table[th_id] = AtomicInc(pe->thread_count) - 1;
		pe->thread_envs[pe->lookup_table[th_id]] = current_t;
#else
		pe->lookup_table[th_id] = pe->thread_count++;
		pe->thread_envs[pe->lookup_table[th_id]] = current_t;
#endif
	} else {
		current_t = pe->thread_envs[pe->lookup_table[th_id]];
		update_tesp(current_t, esp);
	}

	
	update_pcounters(pe, mw);
	if(IS_WITHIN_RANGE((ADDRINT) ip, current_t->code_range)) {
		update_tcounters(current_t, addr, ip, mw);
	} else {
		int i = get_dll(current_t, ip);
		if (i != -1) {
			DLL_ENV * current_d = current_t->dll_envs[i];
			update_dcounters(current_t, current_d, ip, mw);
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

			// THIRD VERSION (READY TO BE THE FASTEST)
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


SHM_PROCESS_ENV ** monitored_processes;

/* ===================================================================== */
/* Main */
/* ===================================================================== */
int main(int argc, char *argv[]) {



	//using namespace boost::interprocess;


	//Create a shared memory object.
	//shared_memory_object shm (open_or_create, "MySharedMemory", read_write);
	//shared_memory_object::remove("MySharedMemory");

	trace = fopen(MEPRO_LOG, "w");
	if (trace == NULL) return 0;
	if (PIN_Init(argc, argv)) return Usage();

	pe = (PROCESS_ENV *) malloc(sizeof(pe));
	memset(pe->lookup_table, -1, sizeof(INT32) * 2048);
	pe->thread_count = 0;


	//monitored_processes = (SHM_PROCESS_ENV **) calloc(MAX_PROCESS_COUNT, sizeof(SHM_PROCESS_ENV));
	fprintf(trace, "[*] Will use %d bytes of contigous memory\n", sizeof(SHM_PROCESS_ENV) * MAX_PROCESS_COUNT);

	//monitored_processes = (SHM_PROCESS_ENV **)  CreateSharedRegion("test_area", sizeof(SHM_PROCESS_ENV) * MAX_PROCESS_COUNT);
	//memset(monitored_processes, NULL, sizeof(SHM_PROCESS_ENV) * MAX_PROCESS_COUNT);
	//CloseSharedRegion("test_area", monitored_processes);



	//attached_processes = (PROCESS_ENV **) calloc(32, sizeof(PROCESS_ENV *));

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
