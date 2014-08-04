#include <stdio.h>

int main(int argc, char *argv[]) {

	/*
	int i = 0;
	char buffer[2048];
	char out[2048];
	for (i = 0; i < 2048; i++) {
		buffer[i] = 'd';
	}
	memcpy(out, buffer, 2048);
	*/

	char * arr = "ciao come stai";
	char p[32];
	//char * p = (char *) malloc(strlen(arr) + 1);
	int len = strlen(arr) + 1;

	printf("%p\n", p);

	__asm {
		mov ecx, len;
		lea edi, p;
		mov esi, arr;
		cld	
		rep movs;
 	}

 	printf("%s\n", p);
 	getchar();
	return 0;
}