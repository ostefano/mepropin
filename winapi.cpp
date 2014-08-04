#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <strsafe.h>
#include <malloc.h>

#include "winapi.h"
#include <Dbghelp.h>
#include <Winternl.h>

#include "common.h"

#define LDR_DOSHEADER_OFFSET			0x03c
#define LDR_NTHEADER_OFFSET				0x18

typedef NTSTATUS(*RtlUnicodeStringToAnsiStringRev)(PANSI_STRING, PCUNICODE_STRING, BOOLEAN);

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

/*


VOID UpdateESPlimits(int p_index, ULONG saved_esp, ULONG thread_address) {
	ASSERT(saved_esp != 0);
	// Update the ESPs only if the thread is not new
	int t_index = THREAD_getThreadIndex(p_index, thread_address);
	if(t_index != -1) {
		THREAD_ENV * current_t = &_attachedProcessesENV[p_index].threads[t_index];
		ASSERT(current_t != NULL);
		if(saved_esp > current_t->esp_min) {
			current_t->esp_min = 0;
			if(saved_esp > current_t->esp_max) {
				#if DEBUG_ESP
				DbgPrint("[STACK] [Thread %08x] Old ESP max %08x [New ESP max %08x]\n", current_t->address, current_t->esp_max, saved_esp);
				#endif
				current_t->esp_max = saved_esp;
			}
		} else {
			#if DEBUG_ESP
			DbgPrint("[STACK] [Thread %08x] Old ESP min %08x [New ESP min %08x]\n", current_t->address, current_t->esp_min, saved_esp);
			#endif
			current_t->esp_min = saved_esp;
		}
	}
}
*/

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

void pe_fill_dlls(FILE * trace, THREAD_ENV *tenv) {
		
	ANSI_STRING temp;
	HMODULE hDLL = LoadLibrary("ntdll.dll");
	
	PLDR_DATA_ENTRY cursor;
	cursor = firstLdrDataEntry();
	while(cursor->BaseAddress) { 

		DLL_ENV * dll = (DLL_ENV *) malloc(sizeof(DLL_ENV));

		DWORD ImageBaseAddress = (DWORD) cursor->BaseAddress;
		DWORD offset_dosheader = *(DWORD *) (ImageBaseAddress + LDR_DOSHEADER_OFFSET);
		DWORD offset_ntheader = LDR_NTHEADER_OFFSET;
		IMAGE_OPTIONAL_HEADER * header = (IMAGE_OPTIONAL_HEADER *) (ImageBaseAddress + offset_dosheader + offset_ntheader);

		UINT32 dll_code_start = (UINT32) (ImageBaseAddress + header->BaseOfCode);
		UINT32 dll_code_end = (UINT32) (ImageBaseAddress + header->BaseOfCode + header->SizeOfCode);

		UINT32 dll_bss_start = (UINT32) (ImageBaseAddress + header->BaseOfData);
		UINT32 dll_bss_end = (UINT32) (ImageBaseAddress + header->BaseOfData + header->SizeOfInitializedData + header->SizeOfUninitializedData);

		fprintf(trace, "[!]   Module [%S] loaded at [%p] with EP at [%p]\n", 
			cursor->BaseDllName.Buffer, 
			cursor->BaseAddress, 
			cursor->EntryPoint);
		fprintf(trace, "\t Code range (%p,%p) (%d bytes)\n", dll_code_start, dll_code_end, header->SizeOfCode);
		fprintf(trace, "\t Data range (%p,%p) (%d bytes)\n", dll_bss_start, dll_bss_end,  header->SizeOfInitializedData + header->SizeOfUninitializedData);

		dll->name = (char *) malloc(cursor->BaseDllName.Length+1);
		sprintf_s(dll->name, cursor->BaseDllName.Length, "%S", cursor->BaseDllName.Buffer);
		dll->name[cursor->BaseDllName.Length] = '\0';

		fprintf(trace, "[!!!]\t %s\n", dll->name);

		dll->data_counter = 0;
		dll->stack_counter = 0;
		dll->heap_counter = 0;
		ASSIGN_RANGE(dll->code_range, dll_code_start, dll_code_end);
		ASSIGN_RANGE(dll->data_range, dll_bss_start, dll_bss_end);
		
		tenv->dll_envs[tenv->dll_count++] = dll;
		cursor = (PLDR_DATA_ENTRY)cursor->InMemoryOrderModuleList.Flink;
	}
	FreeLibrary(hDLL);
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



