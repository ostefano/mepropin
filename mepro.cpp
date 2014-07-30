
#include <stdio.h>
#include "pin.H"
#include "winapi.h"

FILE * trace;

typedef void * PVOID;
typedef unsigned long ULONG;

typedef struct {
     PVOID ExceptionList;
     PVOID StackBase;
     PVOID StackLimit;
     PVOID SubSystemTib;
     union
     {
          PVOID FiberData;
          ULONG Version;
     };
     PVOID ArbitraryUserPointer;
     PVOID Self;
} NT_TIB;


typedef struct {
    UINT32 thread_id;

    ADDRINT esp_max;
    ADDRINT esp_min;

    ADDRINT code_range[2];
    ADDRINT data_range[2];
    ADDRINT stack_range[2];

    UINT64 stack_counter;        // All the writes minus the dlls
    UINT64 heap_counter;
    UINT64 data_counter;
} THREAD_ENV;


typedef struct {
    UINT32 process_id;
    CHAR name[64];
    INT32          lookup_table[2048];
    UINT32          thread_count;
    THREAD_ENV *    thread_envs[2048];
} PROCESS_ENV;


PROCESS_ENV * pe;

VOID RecordMemRead(VOID * ip, VOID * addr) {
    fprintf(trace,"%p: R %p\n", ip, addr);
}

VOID RecordMemWrite(INT32 th_id, INT32 mw, VOID * ip, VOID * addr) {

    if(pe->lookup_table[th_id] == -1) {
        pe->thread_envs[pe->thread_count] = (THREAD_ENV *) malloc(sizeof(THREAD_ENV));
        pe->lookup_table[th_id] = pe->thread_count;
        pe->thread_count++;

		UINT64 value;
		UINT64 *teb64_address;
        __asm {
            mov EAX, GS:[0x30]
            mov teb64_address, EAX
        }

		PIN_SafeCopy (&value, teb64_address+0x100, sizeof(UINT64));
		fprintf(trace, "[!] TEB64 address (%016X): %016X\n", teb64_address, *teb64_address);
		if(value == NULL) {
			fprintf(trace, "NOP\n");
		}
		
		UINT32 stack_base;
		UINT32 stack_limit;
		UINT32 *teb32_address = (UINT32 *) teb64_address + (0x2000/4);

		// REMEMBER POINTER ARITHMETIC
		PIN_SafeCopy (&stack_base, teb32_address+1, sizeof(UINT32));
		PIN_SafeCopy (&stack_limit, teb32_address+2, sizeof(UINT32));	
		
		fprintf(trace, "[!] TEB32 address: %p\n", teb32_address);
		fprintf(trace, "[!]       StackBase:	%p\n", stack_base);
		fprintf(trace, "[!]       StackLimit:	%p\n", stack_limit);

        pe->thread_envs[pe->lookup_table[th_id]]->stack_range[0] = (ADDRINT) stack_limit;
		pe->thread_envs[pe->lookup_table[th_id]]->stack_range[1] = (ADDRINT) stack_base;
    }

    if( (ADDRINT) addr >= pe->thread_envs[pe->lookup_table[th_id]]->stack_range[0] &&
        (ADDRINT) addr <= pe->thread_envs[pe->lookup_table[th_id]]->stack_range[1]) {
        pe->thread_envs[pe->lookup_table[th_id]]->stack_counter += mw;
    } else {
        pe->thread_envs[pe->lookup_table[th_id]]->heap_counter += mw;
		//fprintf(trace, "[->] Memory access to no stack... (%p)\n", addr);
    }

}

VOID Instruction(INS ins, VOID *v) {
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        // Note that in some architectures a single memory operand can be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp) ) {


            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_THREAD_ID,
                IARG_MEMORYWRITE_SIZE,
                IARG_INST_PTR,
                
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
    }
}

VOID Fini(INT32 code, VOID *v) {
    
    for (int i = 0; i < 2048; i++) {
        if(pe->lookup_table[i] != -1) {
            fprintf(trace,"[*] Thread stack range [%p, %p]\n", pe->thread_envs[pe->lookup_table[i]]->stack_range[0], pe->thread_envs[pe->lookup_table[i]]->stack_range[1]);
            fprintf(trace,"[*] Thread (%p) wrote %llu bytes on the stack and %llu somewhere else\n", i,
				pe->thread_envs[pe->lookup_table[i]]->stack_counter, 
				pe->thread_envs[pe->lookup_table[i]]->heap_counter);
        }
    }

    fprintf(trace, "#eof\n");
    fclose(trace);




}

INT32 Usage() {
    PIN_ERROR( "This Pintool prints a trace of memory addresses\n"
    + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main */
/* ===================================================================== */
int main(int argc, char *argv[]) {

	DivideByZero();
	trace = fopen("C:\\Users\\Stefano\\Desktop\\mepropin\\pinatrace.out", "w");
    //trace = fopen("C:\\temp\\pinatrace.out", "w");

	if (trace == NULL) return 0;
    if (PIN_Init(argc, argv)) return Usage();
    
    /* Playing with PE */
    pe = (PROCESS_ENV *) malloc(sizeof(pe));
    memset(pe->lookup_table, -1, sizeof(INT32) * 2048);
    pe->thread_count = 0;
    sprintf(pe->name, "TEST.exe", sizeof("TEST.exe"));

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    // Never returns
    PIN_StartProgram();
    return 0;
}
