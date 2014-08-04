#include "common.h"


void get_process_name(char ** name, int pid);
void pe_fill_dlls(FILE * trace, THREAD_ENV * tenv);
int pe_fill_dll(FILE * trace, THREAD_ENV * current_t, ADDRINT ip);
int pe_create_dll(FILE * trace, THREAD_ENV * current_t, ADDRINT ip);
void set_range(FILE * trace, UINT32 * range, char * section);

void print_heaps_info(FILE * trace);
void print_stats(FILE * trace, PROCESS_ENV * p_current);

int DLL_getDllIndex(THREAD_ENV	* current_t, ADDRINT ip);
bool DLL_isInWriteBlackList(char *dll_name);
bool DLL_isInWriteWhiteList(char *dll_name);