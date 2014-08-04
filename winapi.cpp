#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <strsafe.h>
#include <malloc.h>

#include "winapi.h"
#include <Dbghelp.h>
#include <Winternl.h>
#include <TlHelp32.h>

#include "common.h"

#define LDR_DOSHEADER_OFFSET			0x03c
#define LDR_NTHEADER_OFFSET				0x18

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

void get_process_name(char ** name, int pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hSnapshot) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if(Process32First(hSnapshot,&pe32)) {
            do {
				if(pe32.th32ProcessID == pid) {
					*name = (char *) malloc(sizeof(pe32.szExeFile));
					strcpy(*name, pe32.szExeFile);
					break;
				}
           
            } while(Process32Next(hSnapshot,&pe32));
         }
         CloseHandle(hSnapshot);
    }
}

void print_stats(FILE * trace, PROCESS_ENV * pe) {

	for (int i = 0; i < 2048; i++) {
        if(pe->lookup_table[i] != -1) {
            fprintf(trace,"[-] Thread stack range [%p, %p]\n", pe->thread_envs[pe->lookup_table[i]]->stack_range[0], pe->thread_envs[pe->lookup_table[i]]->stack_range[1]);
            fprintf(trace,"[-] Thread (%p) wrote %llu stack, %llu data, and %llu selse\n", i,
				pe->thread_envs[pe->lookup_table[i]]->stack_counter, 
				pe->thread_envs[pe->lookup_table[i]]->data_counter,
				pe->thread_envs[pe->lookup_table[i]]->heap_counter);
        }
    }
	/*
	ULONGLONG total		= 0, tmp_total		= 0;
			ULONGLONG stack		= 0, tmp_stack		= 0;
			ULONGLONG data		= 0, tmp_data		= 0;
			ULONGLONG heap		= 0, tmp_heap		= 0;
			ULONGLONG g_stack	= 0, tmp_g_stack	= 0;
			ULONGLONG g_data	= 0, tmp_g_data		= 0;
			ULONGLONG g_heap	= 0, tmp_g_heap		= 0;

			total = _attachedProcessesENV[p_index].bytecounter;
			for(int j = 0; j < MAX_THREADS; j++) {
				if(!THREAD_EXISTS(_attachedProcessesENV[p_index].threads, j))
					continue;
				stack	+= _attachedProcessesENV[p_index].threads[j].stack_counter;
				data	+= _attachedProcessesENV[p_index].threads[j].data_counter;
				heap	+= _attachedProcessesENV[p_index].threads[j].heap_counter;
				g_stack += _attachedProcessesENV[p_index].threads[j].global_stack_counter;
				g_data  += _attachedProcessesENV[p_index].threads[j].global_data_counter;
				g_heap	+= _attachedProcessesENV[p_index].threads[j].global_heap_counter;
			}

			tmp_total		= total;
			tmp_stack		= stack;
			tmp_data		= data;
			tmp_heap		= heap;
			tmp_g_stack		= g_stack;
			tmp_g_data		= g_data;
			tmp_g_heap		= g_heap;
			total			-= old_total[i];
			stack			-= old_stack[i];	
			data			-= old_data[i];	
			heap			-= old_heap[i];	
			g_stack			-= old_g_stack[i]; 
			g_data			-= old_g_data[i];	
			g_heap			-= old_g_heap[i];
			old_total[i]	= tmp_total;
			old_stack[i]	= tmp_stack;
			old_data[i]		= tmp_data;
			old_heap[i]		= tmp_heap;
			old_g_stack[i]	= tmp_g_stack;
			old_g_data[i]	= tmp_g_data;
			old_g_heap[i]	= tmp_g_heap;


			DbgPrint("[MONITORY][P%02d] Process '%s' [%04d] wrote %I64u (S:%I64u - D:%I64u - H:%I64u) (GS:%I64u - GD:%I64u - GH:%I64u) bytes\n", i,
					_attachedProcessesENV[p_index].name, 
					_attachedProcessesENV[p_index].id,
					total, stack, data, heap, 
					g_stack, g_data, g_heap);
	*/
}

struct ImageSectionInfo {
      char SectionName[8];		//the macro is defined WinNT.h
      char *SectionAddress;
      int SectionSize;
      ImageSectionInfo(const char* name) {
            strcpy(SectionName, name); 
       }
};

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
		  fprintf(trace, "[!]   Region '%s': (%p, %p) (size=%d)\n", 
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

__declspec(naked) PLDR_DATA_ENTRY firstLdrDataEntry() {
	__asm{
		mov eax, fs:[0x30]		// PEB
		mov eax, [eax+0x0C]		// PEB_LDR_DATA
		mov eax, [eax+0x1C]		//InInitializationOrderModuleList
		retn
	}
}

int pe_create_dll(FILE * trace, THREAD_ENV * tenv, ADDRINT ip) {

	UINT32 page_size = 0x2000;

	// FIXME ROUND DOWN AND UP PAGE
	UINT32 dll_code_start = ip - page_size;
	UINT32 dll_code_end = ip - page_size;

	UINT32 dll_bss_start = dll_code_end;
	UINT32 dll_bss_end = dll_bss_start + page_size;

	DLL_ENV * dll = (DLL_ENV *) malloc(sizeof(DLL_ENV));
	fprintf(trace, "[!]   Module [FAKE] loaded for address %p\n", ip);
	fprintf(trace, "\t Code range (%p,%p) (%d bytes)\n", dll_code_start, dll_code_end, page_size);
	fprintf(trace, "\t Data range (%p,%p) (%d bytes)\n", dll_bss_start, dll_bss_end, page_size);

	dll->name = (char *) malloc(strlen("FAKE")+1);
	sprintf_s(dll->name, strlen("FAKE"), "FAKE");
	dll->name[strlen("FAKE")] = '\0';
	dll->data_counter = 0;
	dll->stack_counter = 0;
	dll->heap_counter = 0;
	ASSIGN_RANGE(dll->code_range, dll_code_start, dll_code_end);
	ASSIGN_RANGE(dll->data_range, dll_bss_start, dll_bss_end);
		
	tenv->dll_envs[tenv->dll_count++] = dll;
	return tenv->dll_count-1;
}

int pe_fill_dll(FILE * trace, THREAD_ENV * tenv, ADDRINT ip) {
		
	PLDR_DATA_ENTRY cursor;
	cursor = firstLdrDataEntry();
	while(cursor->BaseAddress) { 

		DWORD ImageBaseAddress = (DWORD) cursor->BaseAddress;
		DWORD offset_dosheader = *(DWORD *) (ImageBaseAddress + LDR_DOSHEADER_OFFSET);
		DWORD offset_ntheader = LDR_NTHEADER_OFFSET;
		IMAGE_OPTIONAL_HEADER * header = (IMAGE_OPTIONAL_HEADER *) (ImageBaseAddress + offset_dosheader + offset_ntheader);

		UINT32 dll_code_start = (UINT32) (ImageBaseAddress + header->BaseOfCode);
		UINT32 dll_code_end = (UINT32) (ImageBaseAddress + header->BaseOfCode + header->SizeOfCode);

		if(ip >= dll_code_start && ip <= dll_code_end) {

			UINT32 dll_bss_start = (UINT32) (ImageBaseAddress + header->BaseOfData);
			UINT32 dll_bss_end = (UINT32) (ImageBaseAddress + header->BaseOfData + header->SizeOfInitializedData + header->SizeOfUninitializedData);
		
			DLL_ENV * dll = (DLL_ENV *) malloc(sizeof(DLL_ENV));
			fprintf(trace, "[!]   Module [%S] loaded at [%p] with EP at [%p]\n", 
				cursor->BaseDllName.Buffer, 
				cursor->BaseAddress, 
				cursor->EntryPoint);
			fprintf(trace, "\t Code range (%p,%p) (%d bytes)\n", dll_code_start, dll_code_end, header->SizeOfCode);
			fprintf(trace, "\t Data range (%p,%p) (%d bytes)\n", dll_bss_start, dll_bss_end,  header->SizeOfInitializedData + header->SizeOfUninitializedData);

			dll->name = (char *) malloc(cursor->BaseDllName.Length+1);
			sprintf_s(dll->name, cursor->BaseDllName.Length, "%S", cursor->BaseDllName.Buffer);
			dll->name[cursor->BaseDllName.Length] = '\0';
			dll->data_counter = 0;
			dll->stack_counter = 0;
			dll->heap_counter = 0;
			ASSIGN_RANGE(dll->code_range, dll_code_start, dll_code_end);
			ASSIGN_RANGE(dll->data_range, dll_bss_start, dll_bss_end);

			tenv->dll_envs[tenv->dll_count++] = dll;
			return tenv->dll_count-1;
		}
		cursor = (PLDR_DATA_ENTRY)cursor->InMemoryOrderModuleList.Flink;
	}
	return tenv->dll_count;
}


void pe_fill_dlls(FILE * trace, THREAD_ENV *tenv) {
		
	PLDR_DATA_ENTRY cursor;
	cursor = firstLdrDataEntry();
	while(cursor->BaseAddress) { 

		DWORD ImageBaseAddress = (DWORD) cursor->BaseAddress;
		DWORD offset_dosheader = *(DWORD *) (ImageBaseAddress + LDR_DOSHEADER_OFFSET);
		DWORD offset_ntheader = LDR_NTHEADER_OFFSET;
		IMAGE_OPTIONAL_HEADER * header = (IMAGE_OPTIONAL_HEADER *) (ImageBaseAddress + offset_dosheader + offset_ntheader);

		UINT32 dll_code_start = (UINT32) (ImageBaseAddress + header->BaseOfCode);
		UINT32 dll_code_end = (UINT32) (ImageBaseAddress + header->BaseOfCode + header->SizeOfCode);

		UINT32 dll_bss_start = (UINT32) (ImageBaseAddress + header->BaseOfData);
		UINT32 dll_bss_end = (UINT32) (ImageBaseAddress + header->BaseOfData + header->SizeOfInitializedData + header->SizeOfUninitializedData);

		DLL_ENV * dll = (DLL_ENV *) malloc(sizeof(DLL_ENV));
		fprintf(trace, "[!]   Module [%S] loaded at [%p] with EP at [%p]\n", 
			cursor->BaseDllName.Buffer, 
			cursor->BaseAddress, 
			cursor->EntryPoint);
		fprintf(trace, "\t Code range (%p,%p) (%d bytes)\n", dll_code_start, dll_code_end, header->SizeOfCode);
		fprintf(trace, "\t Data range (%p,%p) (%d bytes)\n", dll_bss_start, dll_bss_end,  header->SizeOfInitializedData + header->SizeOfUninitializedData);

		dll->name = (char *) malloc(cursor->BaseDllName.Length+1);
		sprintf_s(dll->name, cursor->BaseDllName.Length, "%S", cursor->BaseDllName.Buffer);
		dll->name[cursor->BaseDllName.Length] = '\0';
		dll->data_counter = 0;
		dll->stack_counter = 0;
		dll->heap_counter = 0;
		ASSIGN_RANGE(dll->code_range, dll_code_start, dll_code_end);
		ASSIGN_RANGE(dll->data_range, dll_bss_start, dll_bss_end);
		
		tenv->dll_envs[tenv->dll_count++] = dll;
		cursor = (PLDR_DATA_ENTRY)cursor->InMemoryOrderModuleList.Flink;
	}
}

int DLL_getDllIndex(THREAD_ENV	* current_t, ADDRINT ip) {
	for(int i = 0; i < current_t->dll_count; i++) {
		if(IS_WITHIN_RANGE(ip, (current_t->dll_envs[i]->code_range))) {
			return i;
		}
	}
	return current_t->dll_count;
}

bool DLL_isInWriteBlackList(char *dll_name) {
	static char* dll_blacklist[] = { WRITES_DLL_BLACKLIST };
	int i;
	for(i=0;dll_blacklist[i]!=NULL;i++) {
		if(!strncmp((char*)dll_name, dll_blacklist[i], strlen(dll_blacklist[i]))) {
			return TRUE;
		}
	}
	return FALSE;
}

bool DLL_isInWriteWhiteList(char *dll_name) {
	static char* dll_whitelist[] = { WRITES_DLL_WHITELIST };
	int i;
	for(i=0;dll_whitelist[i]!=NULL;i++) {
		if(!strncmp((char*)dll_name, dll_whitelist[i], strlen(dll_whitelist[i]))) {
			return TRUE;
		}
	}
	return FALSE;
}


void print_heaps_info(FILE * trace) {

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



