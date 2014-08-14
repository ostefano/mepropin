#include <stdio.h>
#include <iostream>
#include <sys/types.h>
#include <stdlib.h>
#include <fstream>

#include "pin.H"
#include "winapi.h"
#include "common.h"

using namespace std;

namespace WIND {
	#include <windows.h>
}

FILE * trace;

KNOB<BOOL> KnobFirstProcess(KNOB_MODE_WRITEONCE, "pintool", "first_process", "1", "If this is the first process to be instrumented");
KNOB<string> KnobPinPath(KNOB_MODE_WRITEONCE, "pintool", "pin_path",  "c_path_to_pin", "Aboslute path to PIN");
KNOB<string> KnobPinName(KNOB_MODE_WRITEONCE, "pintool", "pin_name",  "pin.exe", "Full name of PIN");
KNOB<string> KnobToolPath(KNOB_MODE_WRITEONCE, "pintool", "tool_path", "c_path_to_tool", "Absolute path to tool path");
KNOB<string> KnobToolName(KNOB_MODE_WRITEONCE, "pintool", "tool_name", "dll_name", "Full name of the tool");


#if (WRITES_DLL_INCLUDE_SCHEME & WRITES_DLL_BLACKLIST_SCHEME)
#define IS_DLL_MONITORED(n)		!DLL_isInWriteBlackList(n)
#else
#define IS_DLL_MONITORED(n)		DLL_isInWriteWhiteList(n)
#endif

#if (WRITES_STACK_SCHEME & WRITES_STACK_ALL_SCHEME)
#define	IS_STACK_REGION_IGNORED(t,e,a)		(IS_WITHIN_RANGE((ADDRINT) a, t->stack_range))
#else
#define IS_STACK_REGION_IGNORED(t,e,a)		(e < t->esp_min)
#endif

inline void INFO_FillThreadInfo(SHM_THREAD_ENV * current_t) {
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

	fprintf(trace, "[*] New thread detected\n");
	fprintf(trace, "[!]	 TEB64 address *(%016X): %016X\n", teb64_address, *teb64_address);
	fprintf(trace, "[!]		 WOW64 flag = %p\n", value);
	fprintf(trace, "[!]	 TEB32 address: %p\n", teb32_address);
	fprintf(trace, "[!]		 StackBase:	%p\n", stack_base);
	fprintf(trace, "[!]		 StackLimit:	%p\n", stack_limit);

	current_t->stack_range[0] = (ADDRINT) stack_limit;
	current_t->stack_range[1] = (ADDRINT) stack_base;

	set_range(trace, current_t->data_range, ".data");
	set_range(trace, current_t->code_range, ".text");

	//current_t->esp_max = 0;
	//current_t->esp_min = current_esp;

	DLL_FindAllDlls(trace, current_t);		
}

inline int INFO_GetThreadDllIndex(SHM_THREAD_ENV * current_t, ADDRINT ip) {
	for(int i = 0; i < current_t->dll_count; i++) {
		if(IS_WITHIN_RANGE(ip, current_t->dll_envs[i].code_range)) {
			return i;
		}
	}
	return -1;
}

inline int INFO_GetDllIndex(SHM_THREAD_ENV * current_t, ADDRINT current_ip) {
	int dll_index;
	dll_index = INFO_GetThreadDllIndex(current_t, current_ip);
	if(dll_index == -1) {
		dll_index = DLL_FindDll(trace, current_t, current_ip);
		if(dll_index == -1) {
			dll_index = DLL_CreateDLL(trace, current_t, current_ip);
		}
	}
	ASSERT(dll_index != -1, "Still can't find dll index");
	return dll_index;
}


inline VOID PERF_update_process_counters(SHM_PROCESS_ENV * current_p, UINT64 mw) {
	AtomicAdd(current_p->total_counter, mw);
}

inline VOID PERF_update_thread_counters(SHM_THREAD_ENV * current_t, VOID * addr, VOID * ip, UINT64 mw) {
	if(IS_WITHIN_RANGE((ADDRINT) addr, current_t->data_range)) {
		current_t->data_counter = mw;
		current_t->global_data_counter = mw;
	} else if (IS_WITHIN_RANGE((ADDRINT) addr, current_t->stack_range)) {
		current_t->stack_counter = mw;
		current_t->global_stack_counter = mw;
		if( (ADDRINT) ip >= current_t->esp_max) {
			current_t->llstack_counter = mw;
			current_t->global_slstack_counter = mw;
		}
	} else {
		current_t->heap_counter = mw;
		current_t->global_heap_counter = mw;
	}
}

inline VOID PERF_update_dll_counters(SHM_THREAD_ENV * current_t, SHM_DLL_ENV * current_d, VOID * ip, UINT64 mw) {
	if(IS_DLL_MONITORED(current_d->name)) {
		if(IS_WITHIN_RANGE((ADDRINT) ip, current_t->data_range) || 
			IS_WITHIN_RANGE((ADDRINT) ip, current_d->data_range)) {
			current_d->data_counter = mw;
			current_t->global_data_counter = mw;
		} else if(IS_WITHIN_RANGE((ADDRINT) ip, current_t->stack_range)) {
			current_d->stack_counter = mw;
			current_t->global_stack_counter = mw;
			if((ADDRINT) ip >= current_t->esp_max) {
				current_d->llstack_counter = mw;
				current_t->global_slstack_counter = mw;
			}
		} else {
			current_d->heap_counter = mw;
			current_t->global_heap_counter = mw;
		}
	}
}

inline VOID PERF_update_thread_stackpointer(SHM_THREAD_ENV * current_t, ADDRINT esp) {
	if (current_t->esp_max == 0 && current_t->esp_min == 0) {
		current_t->esp_min = esp;
	} else {
		if(esp > current_t->esp_min) {
			current_t->esp_min = 0;
			if(esp > current_t->esp_max) {
				current_t->esp_max = esp;
			}
		} else {
			current_t->esp_min = esp;
		}
	}
}

PROCESS_ENV * pe;


ADDRINT IsAddressTo(INT32 th_id, VOID * addr, UINT32 esp_value) {
	
	//UINT16
	if(pe->lookup_table[th_id] == -1) {
		return 1;
	}

	if(IS_STACK_REGION_IGNORED(pe->thread_envs[pe->lookup_table[th_id]], esp_value, addr)) {
		return 0;
	}
	return 1;
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

	SHM_THREAD_ENV * current_t;
	SHM_PROCESS_ENV * current_p;// = attached_processes[0];
	ADDRINT esp = PIN_GetContextReg(ctx, REG_ESP);

	if(pe->lookup_table[th_id] == -1) {
		// Atomically increase the counter and since only one thread is holding
		// this th_id, we can be use that only the current thread is updating
		// the lookup table with the updated value (atomically inc'ed)
		current_p->thread_lookup[th_id] = AtomicInc(current_p->thread_count) - 1;
		INFO_FillThreadInfo(&current_p->thread_envs[current_p->thread_lookup[th_id]]); 
	}
	current_t = &current_p->thread_envs[current_p->thread_lookup[th_id]];

	PERF_update_process_counters(current_p, mw);
	PERF_update_thread_stackpointer(current_t, esp);
	if(IS_WITHIN_RANGE((ADDRINT) ip, current_t->code_range)) {
		PERF_update_thread_counters(current_t, addr, ip, mw);
	} else {
		int dll_index = INFO_GetDllIndex(current_t, (ADDRINT) ip);
		PERF_update_dll_counters(current_t, &current_t->dll_envs[dll_index], ip, mw);
	}
	
}

VOID Instruction(INS ins, VOID *v) {
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
		if (INS_MemoryOperandIsWritten(ins, memOp) ) {
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



/* ===================================================================== */
/* Main */
/* ===================================================================== 
int main(int argc, char *argv[]) {

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
	//memset(monitored_processes
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

	fprintf(trace,"[*] Instrumentation INS MODE\n");
	INS_AddInstrumentFunction(Instruction, 0);

	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();
	return 0;
}
*/

// This is used to instrument the child
BOOL FollowChild(CHILD_PROCESS childProcess, VOID * userData) {

    BOOL res;
    INT appArgc;
    CHAR const * const * appArgv;

    OS_PROCESS_ID pid = CHILD_PROCESS_GetId(childProcess);

	
    CHILD_PROCESS_GetCommandLine(childProcess, &appArgc, &appArgv);
	fprintf(trace, "[%d] Launching a child (%s) with pid %d\n", WIND::GetCurrentProcessId(), appArgv[0], pid);

    //Set Pin's command line for child process
    INT pinArgc = 0;
    CHAR const * pinArgv[13];

	// Begin
    string pin = "C:\\Users\\Stefano\\pin\\pin.exe";
	pinArgv[pinArgc++] = pin.c_str();
    pinArgv[pinArgc++] = "-follow_execv";
    
	// -t 
	pinArgv[pinArgc++] = "-t";
	string tool = (KnobToolPath.Value() + "\\" + KnobToolName.Value());
	pinArgv[pinArgc++] = tool.c_str();

	// -pin_path 
	pinArgv[pinArgc++] = "-pin_path";
	string pin_path = KnobPinPath.Value();
	pinArgv[pinArgc++] = pin_path.c_str();
	
	// -tool_path 
	pinArgv[pinArgc++] = "-tool_path";
	string tool_path = KnobToolPath.Value();
	pinArgv[pinArgc++] = tool_path.c_str();
	
	// -tool_name $(PINTOOL_FILE)
	pinArgv[pinArgc++] = "-tool_name";
	string tool_name = KnobToolName.Value();
	pinArgv[pinArgc++] = tool_name.c_str();

	// -firstprocess
	pinArgv[pinArgc++] = "-first_process";
	pinArgv[pinArgc++] = "0";

	// END
    pinArgv[pinArgc++] = "--";

    CHILD_PROCESS_SetPinCommandLine(childProcess, pinArgc, pinArgv);
    return TRUE;
}

WIND::HANDLE _pregion;
WIND::HANDLE _cregion;



SHM_PROCESS_ENV *  _pmemory;
INT32 *				_cmemory;


INT32 _pindex;




VOID Fini2(INT32 code, VOID *v) {
	fclose(trace);
	WIND::UnmapViewOfFile(_pmemory); 
	WIND::CloseHandle(_pregion);
	WIND::CloseHandle(_cregion);
}

int main(INT32 argc, CHAR **argv) {



	PIN_Init(argc, argv);

	CHAR * pname;
	INT32 pid = PIN_GetPid();
	get_process_name(&pname, pid);

	trace = fopen(MEPRO_LOG, "a");
	ASSERT(trace != NULL, "I Need to keep a log");
	if(KnobFirstProcess) {
		fprintf(trace, "[%d] First process instrumented\n", pid);
	} else {
		fprintf(trace, "[%d] Child is born!!!\n", pid);
	}
	fprintf(trace, "[%d] \t name: %s\n", pid, pname); 
	
	_cregion = WIND::CreateFileMapping((WIND::HANDLE)0xFFFFFFFF, NULL, PAGE_READWRITE, 0, sizeof(INT32), "mepro_counter");
    _cmemory = (INT32 *) WIND::MapViewOfFile(_cregion, FILE_MAP_WRITE, 0, 0, sizeof(INT32));
	if(KnobFirstProcess) {
		*_cmemory = 0;
	} else {
		WIND::InterlockedIncrement((long *)_cmemory);
	}
	_pindex = *_cmemory;
	WIND::UnmapViewOfFile(_cmemory); 
	fprintf(trace, "[%d] Index of the process: %d\n", pid, _pindex);

	_pregion = WIND::CreateFileMapping((WIND::HANDLE)0xFFFFFFFF, NULL, PAGE_READWRITE, 0, sizeof(SHM_PROCESS_ENV) * MAX_PROCESS_COUNT, "mepro");
    _pmemory = (SHM_PROCESS_ENV *) WIND::MapViewOfFile(_pregion, FILE_MAP_WRITE, 0, 0, sizeof(SHM_PROCESS_ENV) * MAX_PROCESS_COUNT);
	//_pmemory[_pindex];
	memset(&_pmemory[_pindex], 0, sizeof(SHM_PROCESS_ENV));
	//p_current->process_id = pid;
	//strcpy_s(_pmemory[_pindex]->name, strlen(pname), pname);




    PIN_AddFollowChildProcessFunction(FollowChild, 0);

	PIN_AddFiniFunction(Fini2, 0);
    PIN_StartProgram();
    return 0;
}

