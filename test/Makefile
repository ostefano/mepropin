!include <win32.mak>

TARGETS = repmove.exe fork.exe child.exe
LIBS = Advapi32.lib 

all: $(TARGETS)

#.c.obj:
#	$(cc) /nologo /D"UNICODE" /EHsc /FAsc /c $(INCLUDES) $*.cpp
#
#$(TARGETS): $*.obj dos_threads.obj messagebox.obj wingetopt.obj
#	$(link) /nologo $(ldflags) /SUBSYSTEM:WINDOWS -out:$@ $** $(LIBS)

.c.obj:
	$(cc) /nologo /EHsc /FAsc /c $(INCLUDES) $*.c

.cpp.obj:
	$(cc) /nologo /EHsc /FAsc /c $(INCLUDES) $*.cpp

$(TARGETS): $*.obj 
	$(link) /nologo $(LIBS) -out:$@ $** 

clean:
	del *.obj 
	del *.exe

