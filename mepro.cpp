#include <stdio.h>
#include <iostream>
#include <sys/types.h>
#include <stdlib.h>
#include <io.h>
#include <fstream>

#include "pin.H"
#include "winapi.h"
#include "common.h"

using namespace std;

namespace WIND {
	#include <windows.h>
	#include <TlHelp32.h>
}

#if (WRITES_DLL_INCLUDE_SCHEME & WRITES_DLL_BLACKLIST_SCHEME)
#define IS_DLL_MONITORED(n)		!DLL_isInWriteBlackList(n)
#else
#define IS_DLL_MONITORED(n)		DLL_isInWriteWhiteList(n)
#endif

#if (WRITES_STACK_SCHEME & WRITES_STACK_ALL_SCHEME)
#define	IS_STACK_REGION_IGNORED(t,e,a)		(IS_WITHIN_RANGE((ADDRINT) a, t.stack_range))
#else
#define IS_STACK_REGION_IGNORED(t,e,a)		(e < t.esp_min)
#endif

FILE *				trace;
WIND::HANDLE		_pregion;
WIND::HANDLE		_cregion;
SHM_PROCESS_ENV *	_pmemory;
SHM_PROCESS_ENV *	_pcurrent;
INT32 *				_cmemory;
INT32				_pindex;

KNOB<BOOL> KnobFirstProcess(KNOB_MODE_WRITEONCE, "pintool", "first_process", "1", "If this is the first process to be instrumented");
KNOB<string> KnobPinPath(KNOB_MODE_WRITEONCE, "pintool", "pin_path",  "c_path_to_pin", "Aboslute path to PIN");
KNOB<string> KnobPinName(KNOB_MODE_WRITEONCE, "pintool", "pin_name",  "pin.exe", "Full name of PIN");
KNOB<string> KnobToolPath(KNOB_MODE_WRITEONCE, "pintool", "tool_path", "c_path_to_tool", "Absolute path to tool path");
KNOB<string> KnobToolName(KNOB_MODE_WRITEONCE, "pintool", "tool_name", "dll_name", "Full name of the tool");

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


ADDRINT INST_AffectStack(INT32 th_id, VOID * addr, UINT32 esp_value) {
	
	if(_pcurrent->thread_lookup[th_id] == -1) {
		return 1;
	}

	if(IS_STACK_REGION_IGNORED(_pcurrent->thread_envs[_pcurrent->thread_lookup[th_id]], esp_value, addr)) {
		return 0;
	}
	return 1;
}

VOID INST_RecordMemWrite(INT32 th_id, const CONTEXT * ctx, UINT32 mw, VOID * ip, VOID * addr) {

	SHM_THREAD_ENV * current_t;
	SHM_PROCESS_ENV * current_p;// = attached_processes[0];
	ADDRINT esp = PIN_GetContextReg(ctx, REG_ESP);

	if(_pcurrent->thread_lookup[th_id] == -1) {
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

VOID TOOL_Instruction(INS ins, VOID *v) {
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
		if (INS_MemoryOperandIsWritten(ins, memOp) ) {
			INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)INST_AffectStack, 
				IARG_THREAD_ID, 
				IARG_MEMORYWRITE_EA,
				IARG_REG_VALUE, REG_STACK_PTR,
				IARG_END);
			INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)INST_RecordMemWrite, 
				IARG_THREAD_ID, 
				IARG_CONTEXT,
				IARG_MEMORYWRITE_SIZE,
				IARG_INST_PTR,
				IARG_MEMORYWRITE_EA,
				IARG_END);
		}
	}
}


INT32 TOOL_Usage() {
	PIN_ERROR( "This Pintool prints a trace of memory addresses\n"
		+ KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

BOOL TOOL_FollowChild(CHILD_PROCESS childProcess, VOID * userData) {

	INT pinArgc = 0;
    CHAR const * pinArgv[16];

    INT appArgc;
    CHAR const * const * appArgv;

    OS_PROCESS_ID pid = CHILD_PROCESS_GetId(childProcess);
	OS_PROCESS_ID ppid = WIND::GetCurrentProcessId();
    CHILD_PROCESS_GetCommandLine(childProcess, &appArgc, &appArgv);
	fprintf(trace, "[%d] Process is forking!!\n", ppid);
	fprintf(trace, "[%d] \t Child process (%s) with pid %d is executing\n", ppid, appArgv[0], pid);
	fflush(trace);

	// Begin
	string pin = KnobPinPath.Value() + "\\" + KnobPinName.Value();
	pinArgv[pinArgc++] = pin.c_str();
    
	//-xyzzy -mesgon warning
	pinArgv[pinArgc++] = "-xyzzy";
	pinArgv[pinArgc++] = "-mesgon";
	pinArgv[pinArgc++] = "warning";

	// Follow_exec
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

VOID TOOL_FlushStats() {

}

VOID TOOL_CloseAndClean(INT32 code, VOID *v) {
	TOOL_FlushStats();
	fclose(trace);
	WIND::UnmapViewOfFile(_pmemory); 
	WIND::CloseHandle(_pregion);
	WIND::CloseHandle(_cregion);
}

VOID TOOL_GetProcessName(CHAR ** name, INT32 pid) {
	WIND::HANDLE hSnapshot = WIND::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnapshot) {
		WIND::PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(WIND::PROCESSENTRY32);
		if(WIND::Process32First(hSnapshot,&pe32)) {
			do {
				if(pe32.th32ProcessID == pid) {
					*name = (char *) malloc(sizeof(pe32.szExeFile));
					strcpy(*name, pe32.szExeFile);
					break;
				}
			} while(WIND::Process32Next(hSnapshot,&pe32));
		 }
		 WIND::CloseHandle(hSnapshot);
	}
}

int main(INT32 argc, CHAR **argv) {

	if (PIN_Init(argc, argv)) return TOOL_Usage();

	/**
	 *	Get things as process name and id
	 *	And print some debug info!
	 */
	CHAR * pname;
	INT32 pid = PIN_GetPid();
	TOOL_GetProcessName(&pname, pid);
	ASSERT(pname != NULL, "I need the name of the process!!");

	trace = fopen(MEPRO_LOG, "a");
	ASSERT(trace != NULL, "I Need to keep a log");
	if(KnobFirstProcess) {
		// Reset the file size
		_chsize_s(_fileno(trace), 0);
		fprintf(trace, "[%d] ****************** MEPROPIN initialized ******************\n", pid);
		fprintf(trace, "[%d] Will use %d bytes of shared memory per snapshot\n", pid, sizeof(SHM_PROCESS_ENV) * MAX_PROCESS_COUNT);
		fprintf(trace, "[%d] First process (%s) instrumented\n", pid, pname);
	} else {
		fprintf(trace, "[%d] Child process (%s) instrumented\n", pid, pname);
	}
	
	/**
	 *	Get the number of processes being monitored from SM so we can have an unique ID
	 *	Also, Unmap the memory when done, but do NOT close it, since we want to keep that info alive in SM
	 */
	_cregion = WIND::CreateFileMapping((WIND::HANDLE)0xFFFFFFFF, NULL, PAGE_READWRITE, 0, sizeof(INT32), "mepro_counter");
    ASSERT(_cregion != NULL, "Fatal Error by CreateFileMapping");
	_cmemory = (INT32 *) WIND::MapViewOfFile(_cregion, FILE_MAP_WRITE, 0, 0, sizeof(INT32));
	ASSERT(_cmemory != NULL, "Fatal Error by MapVieOfFile");
	if(KnobFirstProcess) {
		// If this is the first process, the ID is 0 and we have to store the number
		*_cmemory = 0;
	} else {
		// If this is no the first, we increment it (atomically) and we use the new value as index
		WIND::InterlockedIncrement((long *)_cmemory);
	}
	_pindex = *_cmemory;
	WIND::UnmapViewOfFile(_cmemory); 
	fprintf(trace, "[%d] Assigned index (%d) to the process\n", pid, _pindex);
	fflush(trace);

	/**
	 *	Get a pointer to the SHM_PROCESS_ENV structure
	 *	In this case do NOT unmap and to not release the handle (DUH)
	 */
	_pregion = WIND::CreateFileMapping((WIND::HANDLE)0xFFFFFFFF, NULL, PAGE_READWRITE, 0, sizeof(SHM_PROCESS_ENV) * MAX_PROCESS_COUNT, "mepro");
    ASSERT(_pregion != NULL, "Fatal Error by CreateFileMapping");
	_pmemory = (SHM_PROCESS_ENV *) WIND::MapViewOfFile(_pregion, FILE_MAP_WRITE, 0, 0, sizeof(SHM_PROCESS_ENV) * MAX_PROCESS_COUNT);
	ASSERT(_pmemory != NULL, "Fatal Error by MapVieOfFile");
	_pcurrent = &_pmemory[_pindex];

	// Reset all the memory (should be zeroed already)
	memset(&_pmemory[_pindex], 0, sizeof(SHM_PROCESS_ENV));
	// Put pid, name, and set -1 the lookup table
	_pmemory[_pindex].process_id = pid;
	strcpy_s(_pmemory[_pindex].name, strlen(pname) + 1, pname);
	memset(_pmemory[_pindex].thread_lookup, -1, sizeof(INT32) * MAX_THREAD_COUNT);
	// Free the pointer with the name (we do not need it anymore)
	free(pname);
	
	/**
	 *	Ok, do the magic with the instrumentation! Everything is ready!
	 *
	 */
    PIN_AddFollowChildProcessFunction(TOOL_FollowChild, 0);
	//INS_AddInstrumentFunction(TOOL_Instruction, 0);
	PIN_AddFiniFunction(TOOL_CloseAndClean, 0);
    PIN_StartProgram();
    return 0;
}

