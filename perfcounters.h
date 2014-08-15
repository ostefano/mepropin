#ifndef PERF_H
#define PERF_H

#include "common.h"

namespace WIND {
	#include <windows.h>
}

inline BOOL PERF_dll_blacklist_filter(char *dll_name) {
	static char* dll_blacklist[] = { WRITES_DLL_BLACKLIST };
	int i;
	for(i=0;dll_blacklist[i]!=NULL;i++) {
		if(!strncmp((char*)dll_name, dll_blacklist[i], strlen(dll_blacklist[i]))) {
			return TRUE;
		}
	}
	return FALSE;
}

inline BOOL PERF_dll_whitelist_filter(char *dll_name) {
	static char* dll_whitelist[] = { WRITES_DLL_WHITELIST };
	int i;
	for(i=0;dll_whitelist[i]!=NULL;i++) {
		if(!strncmp((char*)dll_name, dll_whitelist[i], strlen(dll_whitelist[i]))) {
			return TRUE;
		}
	}
	return FALSE;
}

inline VOID PERF_update_process_counters(SHM_PROCESS_ENV * current_p, UINT64 mw) {
	WIND::InterlockedExchangeAdd64((long long*)&current_p->total_counter, mw);
}

inline VOID PERF_update_thread_counters(SHM_THREAD_ENV * current_t, ADDRINT addr, ADDRINT ip, UINT64 mw) {
	if(IS_WITHIN_RANGE(addr, current_t->data_range)) {
		current_t->data_counter += mw;
		current_t->global_data_counter += mw;
	} else if (IS_WITHIN_RANGE(addr, current_t->stack_range)) {
		current_t->stack_counter += mw;
		current_t->global_stack_counter += mw;
		if(ip >= current_t->esp_max) {
			current_t->llstack_counter += mw;
			current_t->global_slstack_counter += mw;
		}
	} else {
		current_t->heap_counter += mw;
		current_t->global_heap_counter += mw;
	}
}

inline VOID PERF_update_dll_counters(SHM_THREAD_ENV * current_t, SHM_DLL_ENV * current_d, ADDRINT ip, UINT64 mw) {
	if(IS_DLL_MONITORED(current_d->name)) {
		if(IS_WITHIN_RANGE(ip, current_t->data_range) || 
			IS_WITHIN_RANGE(ip, current_d->data_range)) {
			current_d->data_counter += mw;
			current_t->global_data_counter += mw;
		} else if(IS_WITHIN_RANGE(ip, current_t->stack_range)) {
			current_d->stack_counter += mw;
			current_t->global_stack_counter += mw;
			if(ip >= current_t->esp_max) {
				current_d->llstack_counter += mw;
				current_t->global_slstack_counter += mw;
			}
		} else {
			current_d->heap_counter += mw;
			current_t->global_heap_counter += mw;
		}
	}
}

inline VOID PERF_update_thread_stackpointer(SHM_THREAD_ENV * current_t, ADDRINT esp) {
	if (current_t->esp_max == 0 && current_t->esp_min == 0) {
		current_t->esp_min = esp;
	} else {
		if(esp > current_t->esp_min) {
			current_t->esp_min = 0;
			if(esp > current_t->esp_max) {
				current_t->esp_max = esp;
			}
		} else {
			current_t->esp_min = esp;
		}
	}
}

#endif