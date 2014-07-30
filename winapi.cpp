#include <Windows.h>
#include <stdio.h>

#include "winapi.h"


#define EXPORT_SYM __declspec( dllexport ) 

// divide by zero exception
int DivideByZero()
{

    if(1) {
        return 1;
    }

    volatile unsigned int zero;
    unsigned int i;
    __try 
    { 
        fprintf(stderr, "Going to divide by zero\n");
        zero = 0;
        i  = 1 / zero;
        return 0;
    } 
    __except(GetExceptionCode() == EXCEPTION_INT_DIVIDE_BY_ZERO ? EXCEPTION_EXECUTE_HANDLER : 
        EXCEPTION_CONTINUE_SEARCH)
    { 
        fprintf(stderr, "Catching divide by zero\n");
        fflush(stderr);
        return 1;
    }
    return 0;
}