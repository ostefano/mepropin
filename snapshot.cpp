#include <Windows.h>
#include <stdio.h>

#include "common.h"

void SNP_TakeSnapshot(SHM_PROCESS_ENV * pmem, char UUID[]) {
	char * filename = (char *) malloc(sizeof(strlen(UUID) + strlen(LOG_OUTPUT)));
	//sprintf(filename, "%s%s", UUID, LOG_OUTPUT);
	//FILE * output = fopen(filename, "w");
	FILE *output = fopen(LOG_OUTPUT_TEST, "w");
	fwrite(pmem, sizeof(SHM_PROCESS_ENV), MAX_PROCESS_COUNT, output);
	fclose(output);
	free(filename);
}