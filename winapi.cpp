#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <strsafe.h>
#include <malloc.h>

//#include <cstring>

#include "winapi.h"

#include <Dbghelp.h>

//#include <Ntdef.h>
#include <Subauth.h>

#define EXPORT_SYM __declspec( dllexport ) 


struct ImageSectionInfo
{
      char SectionName[8];//the macro is defined WinNT.h
      char *SectionAddress;
      int SectionSize;
      ImageSectionInfo(const char* name)
      {
            strcpy(SectionName, name); 
       }
};


void get_dll_3(FILE * trace) {
	char * dllImageBase = (char *) GetModuleHandle(NULL);
	IMAGE_NT_HEADERS *pNtHdr = ImageNtHeader(GetModuleHandle(NULL));
	IMAGE_SECTION_HEADER *pSectionHdr = (IMAGE_SECTION_HEADER *) (pNtHdr + 1);
	ImageSectionInfo *pSectionInfo = NULL;
	for ( int i = 0 ; i < pNtHdr->FileHeader.NumberOfSections ; i++ ) {
		char *name = (char*) pSectionHdr->Name;
		if ( memcmp(name, ".text", 5) == 0 ) {
          pSectionInfo = new ImageSectionInfo(".text");
          pSectionInfo->SectionAddress = dllImageBase + pSectionHdr->VirtualAddress;
          pSectionInfo->SectionSize = pSectionHdr->Misc.VirtualSize;
		  fprintf(trace, "[-->] text %d (%p, %p)\n", pSectionInfo->SectionSize, pSectionInfo->SectionAddress, pSectionInfo->SectionAddress + pSectionInfo->SectionSize);
          break;
		}
		pSectionHdr++;
	}
}

#define ASSIGN_RANGE(range, min, max)		range[0] = min; range[1] = max;


VOID set_range(FILE * trace, OUT UINT32 * range, char * section) {
	char * dllImageBase = (char *) GetModuleHandle(NULL);
	IMAGE_NT_HEADERS *pNtHdr = ImageNtHeader(GetModuleHandle(NULL));
	IMAGE_SECTION_HEADER *pSectionHdr = (IMAGE_SECTION_HEADER *) (pNtHdr + 1);
	ImageSectionInfo *pSectionInfo = NULL;
	for ( int i = 0 ; i < pNtHdr->FileHeader.NumberOfSections ; i++ ) {
		char *name = (char*) pSectionHdr->Name;
		if ( memcmp(name, section, 5) == 0 ) {
          pSectionInfo = new ImageSectionInfo(section);
          pSectionInfo->SectionAddress = dllImageBase + pSectionHdr->VirtualAddress;
          pSectionInfo->SectionSize = pSectionHdr->Misc.VirtualSize;
		  fprintf(trace, "[-->] REGION [%s] (%p, %p) (size=%d)\n", 
			  section, 
			  pSectionInfo->SectionAddress, 
			  pSectionInfo->SectionAddress + pSectionInfo->SectionSize,
			  pSectionInfo->SectionSize);
          ASSIGN_RANGE(range, (UINT32) pSectionInfo->SectionAddress, (UINT32) pSectionInfo->SectionAddress + pSectionInfo->SectionSize);
		  break;	  
		}
		pSectionHdr++;
	}
}



UINT32 get_dll_1(FILE * trace) {
	char * dllImageBase = (char *) GetModuleHandle(NULL);
	IMAGE_NT_HEADERS *pNtHdr = ImageNtHeader(GetModuleHandle(NULL));
	IMAGE_SECTION_HEADER *pSectionHdr = (IMAGE_SECTION_HEADER *) (pNtHdr + 1);
	ImageSectionInfo *pSectionInfo = NULL;
	for ( int i = 0 ; i < pNtHdr->FileHeader.NumberOfSections ; i++ ) {
		char *name = (char*) pSectionHdr->Name;
		if ( memcmp(name, ".data", 5) == 0 ) {
          pSectionInfo = new ImageSectionInfo(".data");
          pSectionInfo->SectionAddress = dllImageBase + pSectionHdr->VirtualAddress;
          pSectionInfo->SectionSize = pSectionHdr->Misc.VirtualSize;
		  fprintf(trace, "[-->] data %d (%p, %p)\n", pSectionInfo->SectionSize, pSectionInfo->SectionAddress, pSectionInfo->SectionAddress + pSectionInfo->SectionSize);
          return (UINT32) pSectionInfo->SectionAddress;
		}
		pSectionHdr++;
	}
}

UINT32 get_dll_2(FILE * trace) {
	char * dllImageBase = (char *) GetModuleHandle(NULL);
	IMAGE_NT_HEADERS *pNtHdr = ImageNtHeader(GetModuleHandle(NULL));
	IMAGE_SECTION_HEADER *pSectionHdr = (IMAGE_SECTION_HEADER *) (pNtHdr + 1);
	ImageSectionInfo *pSectionInfo = NULL;
	for ( int i = 0 ; i < pNtHdr->FileHeader.NumberOfSections ; i++ ) {
		char *name = (char*) pSectionHdr->Name;
		if ( memcmp(name, ".data", 5) == 0 ) {
          pSectionInfo = new ImageSectionInfo(".data");
          pSectionInfo->SectionAddress = dllImageBase + pSectionHdr->VirtualAddress;
          pSectionInfo->SectionSize = pSectionHdr->Misc.VirtualSize;
		  fprintf(trace, "[-->] data %d (%p, %p)\n", pSectionInfo->SectionSize, pSectionInfo->SectionAddress, pSectionInfo->SectionAddress + pSectionInfo->SectionSize);
          return (UINT32) pSectionInfo->SectionAddress + pSectionInfo->SectionSize;
		}
		pSectionHdr++;
	}
}

void printdlls(FILE * trace) {
	
	char * dllImageBase = (char *) GetModuleHandle(NULL);
	IMAGE_NT_HEADERS *pNtHdr = ImageNtHeader(GetModuleHandle(NULL));
	IMAGE_SECTION_HEADER *pSectionHdr = (IMAGE_SECTION_HEADER *) (pNtHdr + 1);
	ImageSectionInfo *pSectionInfo = NULL;
	for ( int i = 0 ; i < pNtHdr->FileHeader.NumberOfSections ; i++ ) {
		char *name = (char*) pSectionHdr->Name;
		pSectionInfo = new ImageSectionInfo(name);
        pSectionInfo->SectionAddress = dllImageBase + pSectionHdr->VirtualAddress;
		pSectionInfo->SectionSize = pSectionHdr->Misc.VirtualSize;
		fprintf(trace, "[%s] (%p, %p)\n", name, pSectionInfo->SectionAddress, pSectionInfo->SectionAddress + pSectionInfo->SectionSize);
		pSectionHdr++;
	}
}

void printend(FILE * trace) {


	//get all the heaps in the process
    HANDLE heaps [100];
	DWORD c = ::GetProcessHeaps (100, heaps);
	fprintf (trace, "The process has %d heaps.\n", c);

	//get the default heap and the CRT heap (both are among those retrieved above)
	const HANDLE default_heap = ::GetProcessHeap ();
	const HANDLE crt_heap = (HANDLE) _get_heap_handle ();

	for (unsigned int i = 0; i < c; i++) {
		//query the heap attributes
		ULONG heap_info = 0;
		SIZE_T ret_size = 0;

        if (::HeapQueryInformation (heaps [i], HeapCompatibilityInformation, &heap_info, sizeof (heap_info), &ret_size)) {
			//show the heap attributes

			switch (heap_info) {
				case 0:
					fprintf (trace, "Heap %d is a regular heap.\n", (i + 1));
					break;
                case 1:
					fprintf (trace, "Heap %d is a heap with look-asides (fast heap).\n", (i + 1));
					break;
				case 2:
					fprintf (trace, "Heap %d is a LFH (low-fragmentation) heap.\n", (i + 1));
					break;
                default:
					fprintf (trace, "Heap %d is of unknown type.\n", (i + 1));
					break;
			}

			if (heaps [i] == default_heap) {
				fprintf (trace, " This the DEFAULT process heap.\n");
			}

            if (heaps [i] == crt_heap) {
				fprintf (trace, " This the heap used by the CRT.\n");  
			}

            //walk the heap and show each allocated block inside it
			//(the attributes of each entry will differ between
			//DEBUG and RELEASE builds)

            PROCESS_HEAP_ENTRY entry;
            memset (&entry, 0, sizeof (entry));
            int count = 0;
            while (::HeapWalk (heaps [i], &entry)) {
				if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
					fprintf (trace, " Allocated entry %d: size: %d, overhead: %d.\n", ++count, entry.cbData, entry.cbOverhead);
                }
			}
		}
	}
}


typedef struct LDR_DATA_ENTRY {
	LIST_ENTRY              InMemoryOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_DATA_ENTRY, *PLDR_DATA_ENTRY;



//__declspec(naked) PLDR_DATA_ENTRY firstLdrDataEntry() {
__declspec(naked) PLDR_DATA_ENTRY firstLdrDataEntry() {
	__asm{
		mov eax, fs:[0x30] // PEB
		mov eax, [eax+0x0C] // PEB_LDR_DATA
		mov eax, [eax+0x1C] //InInitializationOrderModuleList
		retn
	}
}


/*
ANSI_STRING temp;
	RtlUnicodeStringToAnsiString(&temp,&module->BaseDllName,true);
	DWORD address = (DWORD) module->BaseAddress;
	DWORD offset_dosheader = *(DWORD *) (address + LDR_DOSHEADER_OFFSET);
	DWORD offset_ntheader = LDR_NTHEADER_OFFSET;
	IMAGE_OPTIONAL_HEADER * header = (IMAGE_OPTIONAL_HEADER *) (address + offset_dosheader + offset_ntheader);

	int len;
	if(temp.Length > MAX_STRING_LEN-1) {
		len = MAX_STRING_LEN-1;
	} else {
		len = temp.Length;
	}
	RtlCopyMemory(dll_name, temp.Buffer, len);	
	dll_name[len] = '\0';

	*dll_code_start = (header->BaseOfCode + address); // address == header->ImageBase
	*dll_code_end = (header->BaseOfCode + address + header->SizeOfCode);

	PAGE_RANGE_ROUND_MAX(*dll_code_end);
	*dll_data_start = *dll_code_end + 1;

	*dll_data_end = *dll_data_start + (header->SizeOfInitializedData + header->SizeofUninitializedData);
	PAGE_RANGE_ROUND_MAX(*dll_data_end);
*/

#define LDR_DOSHEADER_OFFSET			0x03c
#define LDR_NTHEADER_OFFSET				0x18

void printdetails(FILE * trace, DWORD ImageBaseAddress) {
	DWORD offset_dosheader = *(DWORD *) (ImageBaseAddress + LDR_DOSHEADER_OFFSET);
	DWORD offset_ntheader = LDR_NTHEADER_OFFSET;
	IMAGE_OPTIONAL_HEADER * header = (IMAGE_OPTIONAL_HEADER *) (ImageBaseAddress + offset_dosheader + offset_ntheader);

	ULONG * dll_code_start = (ULONG *) (ImageBaseAddress + header->BaseOfCode);
	ULONG * dll_code_end = (ULONG *) (ImageBaseAddress + header->BaseOfCode + header->SizeOfCode);

	ULONG * dll_bss_start = (ULONG *) (ImageBaseAddress + header->BaseOfData);
	ULONG * dll_bss_end = (ULONG *) (ImageBaseAddress + header->BaseOfData + header->SizeOfInitializedData + header->SizeOfUninitializedData);


	fprintf(trace, "\t Code range (%p,%p) (size)\n", dll_code_start, dll_code_end);
	fprintf(trace, "\t Data range (%p,%p) (size)\n", dll_bss_start, dll_bss_end);

}

void pe_fill_dlls(FILE * trace, THREAD_ENV *tenv) {
	
	PLDR_DATA_ENTRY cursor;
	cursor = firstLdrDataEntry();
	while(cursor->BaseAddress) { 
		fprintf(trace, "Module [%S] loaded at [%p] with entrypoint at [%p]\n", 
			cursor->BaseDllName.Buffer, 
			cursor->BaseAddress, 
			cursor->EntryPoint);
		printdetails(trace, (DWORD) cursor->BaseAddress);



		cursor = (PLDR_DATA_ENTRY)cursor->InMemoryOrderModuleList.Flink;
	}
}

void printmod(FILE * trace) {
	
	PLDR_DATA_ENTRY cursor;
	cursor = firstLdrDataEntry();
	while(cursor->BaseAddress) { 
		fprintf(trace, "Module [%S] loaded at [%p] with entrypoint at [%p]\n", 
			cursor->BaseDllName.Buffer, 
			cursor->BaseAddress, 
			cursor->EntryPoint);
		printdetails(trace, (DWORD) cursor->BaseAddress);
		cursor = (PLDR_DATA_ENTRY)cursor->InMemoryOrderModuleList.Flink;
	}
}

// divide by zero exception
int DivideByZero()
{

    if(1) {
        return 1;
    }

    volatile unsigned int zero;
    unsigned int i;
    __try 
    { 
        fprintf(stderr, "Going to divide by zero\n");
        zero = 0;
        i  = 1 / zero;
        return 0;
    } 
    __except(GetExceptionCode() == EXCEPTION_INT_DIVIDE_BY_ZERO ? EXCEPTION_EXECUTE_HANDLER : 
        EXCEPTION_CONTINUE_SEARCH)
    { 
        fprintf(stderr, "Catching divide by zero\n");
        fflush(stderr);
        return 1;
    }
    return 0;
}