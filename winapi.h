#ifndef WINAPI_H
#define WINAPI_H

#include "common.h"


int DLL_FindDll(FILE * trace, SHM_THREAD_ENV * curren_t, ADDRINT ip);
int DLL_CreateDLL(FILE * trace, SHM_THREAD_ENV * current_t, ADDRINT current_ip);

void get_process_name(char ** name, int pid);
void pe_fill_dlls(FILE * trace, THREAD_ENV * tenv);
int pe_fill_dll(FILE * trace, THREAD_ENV * current_t, ADDRINT ip);
int pe_create_dll(FILE * trace, THREAD_ENV * current_t, ADDRINT ip);
void set_range(FILE * trace, UINT32 * range, char * section);

void print_heaps_info(FILE * trace);
void print_stats(FILE * trace, PROCESS_ENV * p_current);

int DLL_getDllIndex(THREAD_ENV * current_t, ADDRINT ip);
bool DLL_isInWriteBlackList(char *dll_name);
bool DLL_isInWriteWhiteList(char *dll_name);

UINT16 AtomicInc(volatile UINT16& mem);
UINT64 AtomicAdd(volatile UINT64& mem, UINT64 summand);
UINT64 AtomicInc(volatile UINT64& mem);


VOID * CreateSharedRegion(char name[], int size_t);
VOID CloseSharedRegion(char name[], VOID * region);



#endif