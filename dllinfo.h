#ifndef DLLINFO_H
#define DLLINFO_H

#include "common.h"

#define LDR_DOSHEADER_OFFSET	0x03c
#define LDR_NTHEADER_OFFSET		0x18

VOID	DLL_FindAllDlls(FILE * trace, SHM_THREAD_ENV *current_t);
INT		DLL_FindDll(FILE * trace, SHM_THREAD_ENV * curren_t, ADDRINT ip);
INT		DLL_CreateDLL(FILE * trace, SHM_THREAD_ENV * current_t, ADDRINT current_ip);

#endif