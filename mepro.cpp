
#include <stdio.h>
#include "pin.H"
#include "winapi.h"


//#include <SDKDDKVer.h>
//#include <winnt.h>



FILE * trace;

typedef void * PVOID;
typedef unsigned long ULONG;

//#define TRACE_EN 1

#ifndef TRACE_EN
    #define TRACE_EN 0
#endif

/*
 * The ID of the buffer
 */
BUFFER_ID bufId;

#define NUM_BUF_PAGES 1024

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
	char name[128];

	ADDRINT data_range[2];
	ADDRINT code_range[2];

	UINT64 stack_counter;
	UINT64 heap_counter;
	UINT64 data_counter;
} DLL_ENV;


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

	
	UINT64 global_stack_counter;	// All the writes plus the dlls
	UINT64 global_heap_counter;
	UINT64 global_data_counter;

	UINT16	dll_count;
	DLL_ENV	* dll_envs[2048];
} THREAD_ENV;


typedef struct {
    UINT32 process_id;
    CHAR name[64];
	UINT64 bytecounter;
    INT32          lookup_table[2048];

    UINT16          thread_count;
    THREAD_ENV *    thread_envs[2048];
} PROCESS_ENV;


PROCESS_ENV * pe;

VOID RecordMemRead(VOID * ip, VOID * addr) {
    fprintf(trace,"%p: R %p\n", ip, addr);
}


#define COPY_RANGE(range_dst, range_src)	range_dst[0] = range_src[0]; range_dst[1] = range_src[1];
#define ASSIGN_RANGE(range, min, max)		range[0] = min; range[1] = max;
#define IS_WITHIN_RANGE(value, range)		(value >= range[0] && value <= range[1])


VOID pe_fill_dlls(THREAD_ENV *tenv) {

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

		//pe->thread_envs[pe->lookup_table[th_id]]->data_range[0] = (ADDRINT) get_dll_1(trace);
		//pe->thread_envs[pe->lookup_table[th_id]]->data_range[1] = (ADDRINT) get_dll_2(trace);


		set_range(trace, pe->thread_envs[pe->lookup_table[th_id]]->data_range, ".data");
		set_range(trace, pe->thread_envs[pe->lookup_table[th_id]]->code_range, ".text");
		
		pe_fill_dlls(pe->thread_envs[pe->lookup_table[th_id]]);


		//pe_fill_process(pe);
		//pe_fill_thread(pe->thread_envs[pe->lookup_table[th_id]]);
		//pe_fill_dlls(pe->thread_envs[pe->lookup_table[th_id]]);

    }

    if( (ADDRINT) addr >= pe->thread_envs[pe->lookup_table[th_id]]->stack_range[0] &&
        (ADDRINT) addr <= pe->thread_envs[pe->lookup_table[th_id]]->stack_range[1]) {
        pe->thread_envs[pe->lookup_table[th_id]]->stack_counter += mw;
    } else {

		if( (ADDRINT) addr >= pe->thread_envs[pe->lookup_table[th_id]]->data_range[0] &&
			(ADDRINT) addr <= pe->thread_envs[pe->lookup_table[th_id]]->data_range[1]) {
			pe->thread_envs[pe->lookup_table[th_id]]->data_counter += mw;
		} else {
			pe->thread_envs[pe->lookup_table[th_id]]->heap_counter += mw;
			fprintf(trace, "[->] Memory access unreck... (%p)\n", addr);
		}
		//fprintf(trace, "[->] Memory access to no stack... (%p)\n", addr);
    }

}

struct MEMREF {
    ADDRINT     pc;
    ADDRINT     ea;
    UINT32      size;
    BOOL        read;
	UINT32		tid;

};

VOID Trace(TRACE trace, VOID *v) {
    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl=BBL_Next(bbl)) {
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins=INS_Next(ins)) {
            UINT32 memoryOperands = INS_MemoryOperandCount(ins);
            for (UINT32 memOp = 0; memOp < memoryOperands; memOp++) {
                UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
                if (INS_MemoryOperandIsWritten(ins, memOp)) {
                    INS_InsertFillBuffer(ins, IPOINT_BEFORE, bufId,
                                         IARG_INST_PTR, offsetof(struct MEMREF, pc),
                                         IARG_MEMORYOP_EA, memOp, offsetof(struct MEMREF, ea),
                                         IARG_UINT32, refSize, offsetof(struct MEMREF, size), 
                                         IARG_BOOL, FALSE, offsetof(struct MEMREF, read),
										 IARG_THREAD_ID, offsetof(struct MEMREF, tid), 
                                         IARG_END);
                }
            }
        }
    }
}


VOID Instruction(INS ins, VOID *v) {
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
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
            fprintf(trace,"[*] Thread (%p) wrote %llu stack, %llu data, and %llu selse\n", i,
				pe->thread_envs[pe->lookup_table[i]]->stack_counter, 
				pe->thread_envs[pe->lookup_table[i]]->data_counter,
				pe->thread_envs[pe->lookup_table[i]]->heap_counter);
        }
    }

	printdlls(trace);

	fprintf(trace, "[*] TTT\n");

	//printend(trace);

	printmod(trace);

	get_dll_3(trace);


    fprintf(trace, "#eof\n");
    fclose(trace);
}

INT32 Usage() {
    PIN_ERROR( "This Pintool prints a trace of memory addresses\n"
    + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}


VOID * BufferFull(BUFFER_ID id, THREADID tid, const CONTEXT *ctxt, VOID *buf, UINT64 numElements, VOID *v) {
    /*
    This code will work - but it is very slow, so for testing purposes we run with the Knob turned off
    */

	return buf;
	/*
    if (KnobDoWriteToOutputFile)
    {
        PIN_GetLock(&fileLock, 1);

        struct MEMREF * reference=(struct MEMREF*)buf;

        for(UINT64 i=0; i<numElements; i++, reference++)
        {
            if (reference->ea != 0)
                ofile << tid << "   "  << reference->pc << "   " << reference->ea << endl;
        }
        PIN_ReleaseLock(&fileLock);
    }

    return buf;
	*/
}

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v) {
    // There is a new MLOG for every thread.  Opens the output file.
    //MLOG * mlog = new MLOG(tid);

    // A thread will need to look up its MLOG, so save pointer in TLS
    //PIN_SetThreadData(mlog_key, mlog, tid);
	fprintf(trace,"[*] Thread (%p) started\n", tid); 
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




#if TRACE_EN
    fprintf(trace,"[*] Instrumentation TRACE MODE\n");
	bufId = PIN_DefineTraceBuffer(sizeof(struct MEMREF), NUM_BUF_PAGES, BufferFull, 0);
	TRACE_AddInstrumentFunction(Trace, 0);
	PIN_AddThreadStartFunction(ThreadStart, 0);
#else
    fprintf(trace,"[*] Instrumentation INS MODE\n");
    INS_AddInstrumentFunction(Instruction, 0);
#endif

    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
