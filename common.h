#ifndef COMMON_H
#define COMMON_H

//#define ATTACHED_PROCESSES_MAX
#define MEPRO_LOG 							"C:\\Users\\Stefano\\mepropin\\pinatrace.out"

#if !defined(PIN_H)
#define ADDRINT 							UINT32
#endif

#define COPY_RANGE(range_dst, range_src)	range_dst[0] = range_src[0]; range_dst[1] = range_src[1];
#define ASSIGN_RANGE(range, min, max)		range[0] = min; range[1] = max;
#define IS_WITHIN_RANGE(value, range)		(value >= range[0] && value <= range[1])

#define WRITES_STACK_ALL_SCHEME				0x01
#define WRITES_STACK_LLS_SCHEME				0x02
#define WRITES_STACK_SCHEME					(WRITES_STACK_ALL_SCHEME)

#define WRITES_DLL_WHITELIST_SCHEME			0x01
#define WRITES_DLL_BLACKLIST_SCHEME			0x02
#define WRITES_DLL_INCLUDE_SCHEME			(WRITES_DLL_BLACKLIST_SCHEME)
#define WRITES_DLL_WHITELIST				"kernel32.dll", NULL
#define WRITES_DLL_BLACKLIST				"USER32.dll", "ntdll.dll", NULL	

#define ADD_UNKNOWN_DLLS					0
#define PROTECT_FROM_RACE					1

#if PROTECT_FROM_RACE
#define ADD(a1,a2)		AtomicAdd(a1, a2)
#else
#define ADD(a1,a2)		a1 += a2
#endif

#if (WRITES_DLL_INCLUDE_SCHEME & WRITES_DLL_BLACKLIST_SCHEME)
#define IS_MONITORED(n)		!DLL_isInWriteBlackList(n)
#else
#define IS_MONITORED(n)		DLL_isInWriteWhiteList(n)
#endif


typedef void * PVOID;
typedef unsigned long ULONG;

typedef struct {
	char * name;
	ADDRINT data_range[2];
	ADDRINT code_range[2];
	UINT64 slstack_counter;
	UINT64 stack_counter;
	UINT64 heap_counter;
	UINT64 data_counter;
} DLL_ENV;

typedef struct {
	UINT32 thread_id;

	ADDRINT esp_max;
	ADDRINT esp_min;

	ADDRINT code_range[2];
	ADDRINT data_range[2];
	ADDRINT stack_range[2];

	UINT64 slstack_counter;			// All the writes minus the dlls
	UINT64 stack_counter;
	UINT64 heap_counter;
	UINT64 data_counter;
	UINT64 global_slstack_counter;	// All the writes plus the dlls
	UINT64 global_stack_counter;	
	UINT64 global_heap_counter;
	UINT64 global_data_counter;

	UINT16	dll_count;
	DLL_ENV	* dll_envs[2048];
} THREAD_ENV;

typedef struct {
	UINT32 process_id;
	CHAR name[64];
	UINT64 bytecounter;
	INT32 lookup_table[2048];
	UINT16 thread_count;
	THREAD_ENV * thread_envs[2048];
} PROCESS_ENV;

#endif