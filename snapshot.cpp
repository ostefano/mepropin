#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "common.h"

void generate_filename(char * ptr, int id_int) {
  char * id = (char *) malloc(sizeof(char)*4);
  _snprintf(id, (sizeof(char)*4), "%03d", id_int);
//  printf("[1] ID %s\n", id);

  char * date = (char *) malloc(sizeof(char)*64);
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  strftime(date, (sizeof(char)*64), "date_%y%m%d_%H%M", t);
//  printf("[2] Current Date: %s\n", date);

  _snprintf(ptr, (sizeof(char)*64 + 4 + strlen(LOG_OUTPUT)), "%s\\%s_s%s.log", LOG_OUTPUT, date, id);
}


UINT64 get_timestamp() {
	LARGE_INTEGER timer;
	QueryPerformanceFrequency(&timer);
	return timer.QuadPart;
}

void SNP_TakeSnapshot(SHM_PROCESS_ENV * pmem, int id) {
	UINT64 timer = get_timestamp();
	for(int i = 0; i < MAX_PROCESS_COUNT; i++) {
		pmem[i].timestamp = timer;
	}
	char * filename = (char *) malloc(sizeof(char)*128);
	generate_filename(filename, id);
	FILE * output = fopen(filename, "w");
	fwrite(pmem, sizeof(SHM_PROCESS_ENV), MAX_PROCESS_COUNT, output);
	fclose(output);
	free(filename);
}