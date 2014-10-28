#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <Winternl.h>
#include <stdint.h>

#include "common.h"
#include "dllinfo.h"

typedef struct LDR_DATA_ENTRY {
	LIST_ENTRY		InMemoryOrderModuleList;
	PVOID			BaseAddress;
	PVOID			EntryPoint;
	ULONG			SizeOfImage;
	UNICODE_STRING 	FullDllName;
	UNICODE_STRING 	BaseDllName;
	ULONG			Flags;
	SHORT			LoadCount;
	SHORT			TlsIndex;
	LIST_ENTRY		HashTableEntry;
	ULONG			TimeDateStamp;
} LDR_DATA_ENTRY, *PLDR_DATA_ENTRY;

__declspec(naked) PLDR_DATA_ENTRY firstLdrDataEntry() {
	__asm{
		mov eax, fs:[0x30]		//	PEB
		mov eax, [eax+0x0C]		//	PEB_LDR_DATA
		mov eax, [eax+0x1C]		//	InInitializationOrderModuleList
		retn
	}
}

char key[16] = {0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf};

uint64_t siphash24(const void *src,
                   unsigned long src_sz,
                   const char key[16]);

VOID DLL_FindAllDlls(FILE * trace, SHM_THREAD_ENV *current_t) {
		
	PLDR_DATA_ENTRY cursor;
	cursor = firstLdrDataEntry();
	while(cursor->BaseAddress) { 

		DWORD ImageBaseAddress = (DWORD) cursor->BaseAddress;
		DWORD offset_dosheader = *(DWORD *) (ImageBaseAddress + LDR_DOSHEADER_OFFSET);
		DWORD offset_ntheader = LDR_NTHEADER_OFFSET;
		IMAGE_OPTIONAL_HEADER * header = (IMAGE_OPTIONAL_HEADER *) (ImageBaseAddress + offset_dosheader + offset_ntheader);

		UINT32 dll_code_start	= (UINT32) (ImageBaseAddress + header->BaseOfCode);
		UINT32 dll_code_end		= (UINT32) (ImageBaseAddress + header->BaseOfCode + header->SizeOfCode);

		UINT32 dll_bss_start	= (UINT32) (ImageBaseAddress + header->BaseOfData);
		UINT32 dll_bss_end		= (UINT32) (ImageBaseAddress + header->BaseOfData + header->SizeOfInitializedData + header->SizeOfUninitializedData);
#if PRINT_THREAD_MODULES_INFO
		fprintf(trace, "[!]   Module [%S] loaded at [%p] with EP at [%p]\n", cursor->BaseDllName.Buffer, cursor->BaseAddress, cursor->EntryPoint);
		fprintf(trace, "\t Code range (%p,%p) (%d bytes)\n", dll_code_start, dll_code_end, header->SizeOfCode);
		fprintf(trace, "\t Data range (%p,%p) (%d bytes)\n", dll_bss_start, dll_bss_end,  header->SizeOfInitializedData + header->SizeOfUninitializedData);
#endif
		SHM_DLL_ENV * empty_dll = &current_t->dll_envs[current_t->dll_count];
		sprintf_s(empty_dll->name, cursor->BaseDllName.Length, "%S", cursor->BaseDllName.Buffer);
		empty_dll->dll_id = siphash24(empty_dll->name, strlen(empty_dll->name), key);
		ASSIGN_RANGE(empty_dll->code_range,	dll_code_start,	dll_code_end);
		ASSIGN_RANGE(empty_dll->data_range,	dll_bss_start,	dll_bss_end);
		
		//current_t->dll_count++;
		InterlockedIncrement16((short *)&current_t->dll_count);

		cursor = (PLDR_DATA_ENTRY)cursor->InMemoryOrderModuleList.Flink;
	}
}

INT DLL_FindDll(FILE * trace, SHM_THREAD_ENV * current_t, ADDRINT ip) {
		
	PLDR_DATA_ENTRY cursor;
	cursor = firstLdrDataEntry();
	while(cursor->BaseAddress) { 
		DWORD ImageBaseAddress = (DWORD) cursor->BaseAddress;
		DWORD offset_dosheader = *(DWORD *) (ImageBaseAddress + LDR_DOSHEADER_OFFSET);
		DWORD offset_ntheader = LDR_NTHEADER_OFFSET;
		IMAGE_OPTIONAL_HEADER * header = (IMAGE_OPTIONAL_HEADER *) (ImageBaseAddress + offset_dosheader + offset_ntheader);

		UINT32 dll_code_start	= (UINT32) (ImageBaseAddress + header->BaseOfCode);
		UINT32 dll_code_end		= (UINT32) (ImageBaseAddress + header->BaseOfCode + header->SizeOfCode);

		if(ip >= dll_code_start && ip <= dll_code_end) {

			UINT32 dll_bss_start	= (UINT32) (ImageBaseAddress + header->BaseOfData);
			UINT32 dll_bss_end		= (UINT32) (ImageBaseAddress + header->BaseOfData + header->SizeOfInitializedData + header->SizeOfUninitializedData);
#if PRINT_THREAD_MODULES_INFO			
			fprintf(trace, "[!]   Module [%S] loaded at [%p] with EP at [%p]\n", cursor->BaseDllName.Buffer, cursor->BaseAddress, cursor->EntryPoint);
			fprintf(trace, "\t Code range (%p,%p) (%d bytes)\n", dll_code_start, dll_code_end, header->SizeOfCode);
			fprintf(trace, "\t Data range (%p,%p) (%d bytes)\n", dll_bss_start, dll_bss_end,  header->SizeOfInitializedData + header->SizeOfUninitializedData);
#endif			
			SHM_DLL_ENV * empty_dll = &current_t->dll_envs[current_t->dll_count];
			sprintf_s(empty_dll->name, cursor->BaseDllName.Length, "%S", cursor->BaseDllName.Buffer);
			empty_dll->dll_id = siphash24(empty_dll->name, strlen(empty_dll->name), key);
			ASSIGN_RANGE(empty_dll->code_range,	dll_code_start,	dll_code_end);
			ASSIGN_RANGE(empty_dll->data_range,	dll_bss_start,	dll_bss_end);
			
			//return current_t->dll_count++;
			return InterlockedIncrement16((short *)&current_t->dll_count);
		}
		cursor = (PLDR_DATA_ENTRY)cursor->InMemoryOrderModuleList.Flink;
	}
	return -1;
}

INT DLL_CreateDLL(FILE * trace, SHM_THREAD_ENV * current_t, ADDRINT current_ip) {

	SYSTEM_INFO si;
    GetSystemInfo(&si);

	UINT32 page_size		= si.dwPageSize;
	UINT32 page_top			= ROUND_UP(current_ip, page_size);
	UINT32 dll_code_start	= page_top - page_size;
	UINT32 dll_code_end		= page_top;
	UINT32 dll_bss_start	= dll_code_end;
	UINT32 dll_bss_end		= dll_bss_start + page_size;
#if PRINT_THREAD_MODULES_INFO
	fprintf(trace, "[!]   Module [FAKE] loaded for address %p\n", current_ip);
	fprintf(trace, "\t Code range (%p,%p) (%d bytes)\n", dll_code_start, dll_code_end, page_size);
	fprintf(trace, "\t Data range (%p,%p) (%d bytes)\n", dll_bss_start, dll_bss_end, page_size);
#endif	
	SHM_DLL_ENV * empty_dll = &current_t->dll_envs[current_t->dll_count];
	strcpy_s(empty_dll->name, strlen("fake.dll"), "fake.dll");
	empty_dll->dll_id = siphash24(empty_dll->name, strlen(empty_dll->name), key);
	ASSIGN_RANGE(empty_dll->code_range,	dll_code_start,	dll_code_end);
	ASSIGN_RANGE(empty_dll->data_range,	dll_bss_start,	dll_bss_end);
	
	//return current_t->dll_count++;
	return InterlockedIncrement16((short *)&current_t->dll_count);
}
