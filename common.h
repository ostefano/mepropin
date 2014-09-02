#ifndef COMMON_H
#define COMMON_H

#define	PRINT_THREAD_INFO					0
#define PRINT_THREAD_MODULES_INFO			0

#define SPINNER_ENABLE						1
#define SPINNER_ENABLE_LOG					1
#define SPINNER_ENABLE_SLEEP				1000
#define SPINNER_SNAPSHOT_LIMIT				20

#define LOG_OUTPUT							"C:\\Users\\Stefano\\mepropin\\"
#define LOG_OUTPUT_TEST						"C:\\Users\\Stefano\\mepropin\\pinatrace.log"
#define MEPRO_LOG 							"C:\\Users\\Stefano\\mepropin\\pinatrace.out"

#if !defined(PIN_H)
#define ADDRINT 							UINT32
#endif

#define ROUND_UP(in, multiple)				((in + multiple - 1) & ~(multiple - 1));
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

#define MAX_CHAR_COUNT						128
#define MAX_THREAD_COUNT					64
#define MAX_DLL_COUNT						256
#define MAX_PROCESS_COUNT					4

#if (WRITES_STACK_SCHEME & WRITES_STACK_ALL_SCHEME)
#define	IS_STACK_REGION_IGNORED(t,e,a)		(IS_WITHIN_RANGE((ADDRINT) a, t.stack_range))
#else
#define IS_STACK_REGION_IGNORED(t,e,a)		(e < t.esp_min)
#endif

#if (WRITES_DLL_INCLUDE_SCHEME & WRITES_DLL_BLACKLIST_SCHEME)
#define IS_DLL_MONITORED(n)		!PERF_dll_blacklist_filter(n)
#else
#define IS_DLL_MONITORED(n)		PERF_dll_whitelist_filter(n)
#endif

typedef void * PVOID;
typedef unsigned long ULONG;

typedef struct {
	short max_char_count;
	short max_thread_count;
	short max_dll_count;
} SHM_CONFIG;

typedef struct {
	CHAR name[MAX_CHAR_COUNT];
	ADDRINT data_range[2];
	ADDRINT code_range[2];

	UINT64 llstack_counter;
	UINT64 stack_counter;
	UINT64 heap_counter;
	UINT64 data_counter;
} SHM_DLL_ENV;

typedef struct {
	UINT32 thread_id;

	ADDRINT esp_max;
	ADDRINT esp_min;

	ADDRINT code_range[2];
	ADDRINT data_range[2];
	ADDRINT stack_range[2];

	UINT64 llstack_counter;			// All the writes minus the dlls
	UINT64 stack_counter;
	UINT64 heap_counter;
	UINT64 data_counter;

	UINT64 global_slstack_counter;	// All the writes plus the dlls
	UINT64 global_stack_counter;	
	UINT64 global_heap_counter;
	UINT64 global_data_counter;

	UINT16		dll_count;
	UINT32		dll_lookup[MAX_DLL_COUNT];
	SHM_DLL_ENV	dll_envs[MAX_DLL_COUNT];
} SHM_THREAD_ENV;

typedef struct {
	BOOL x64;
	CHAR name[MAX_CHAR_COUNT];
	UINT32 process_id;
	UINT64 total_counter;

	UINT16			thread_count;
	UINT32			thread_lookup[MAX_THREAD_COUNT];
	SHM_THREAD_ENV	thread_envs[MAX_THREAD_COUNT];
} SHM_PROCESS_ENV;


#endif