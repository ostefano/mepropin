#include <stdio.h>
#include <Windows.h>
#include <malloc.h>

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
