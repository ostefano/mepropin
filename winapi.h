
#include "common.h"

void printend(FILE * trace);
void pe_fill_dlls(FILE * trace, THREAD_ENV * tenv);
void set_range(FILE * trace, UINT32 * range, char * section);
void print_stats(FILE * trace, PROCESS_ENV * p_current);