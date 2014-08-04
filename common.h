#ifndef COMMON_H
#define COMMON_H

#if !defined(PIN_H)
#define ADDRINT UINT32
#endif

#define COPY_RANGE(range_dst, range_src)	range_dst[0] = range_src[0]; range_dst[1] = range_src[1];
#define ASSIGN_RANGE(range, min, max)		range[0] = min; range[1] = max;
#define IS_WITHIN_RANGE(value, range)		(value >= range[0] && value <= range[1])

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

	UINT64 slstack_counter;
    UINT64 stack_counter;        // All the writes minus the dlls
    UINT64 heap_counter;
    UINT64 data_counter;

	UINT64 global_slstack_counter;
	UINT64 global_stack_counter;	// All the writes plus the dlls
	UINT64 global_heap_counter;
	UINT64 global_data_counter;

	UINT16	dll_count;
	DLL_ENV	* dll_envs[2048];
} THREAD_ENV;


typedef struct {
    UINT32 process_id;
    CHAR name[64];
	UINT64 bytecounter;
    INT32          lookup_table[2048];

    UINT16          thread_count;
    THREAD_ENV *    thread_envs[2048];
} PROCESS_ENV;


#endif