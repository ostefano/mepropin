//#include <Windows.h>


/*
typedef struct LDR_DATA_ENTRY {
//	LIST_ENTRY              InMemoryOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
//	UNICODE_STRING          FullDllName;
//	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
//	SHORT                   LoadCount;
//	SHORT                   TlsIndex;
//	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_DATA_ENTRY, *PLDR_DATA_ENTRY;
*/
int DivideByZero();
void printdlls(FILE * trace);
void printend(FILE * trace);
UINT32 get_dll_1(FILE * trace);
UINT32 get_dll_2(FILE * trace);
