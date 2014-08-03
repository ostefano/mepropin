UNAME=$(shell uname)
PINTOOL_NAME=mepro

#####  WINDOWS
ATTACH_TO_TARGET=true
TARGET_BIN=C:\\Windows\\SysWOW64\\notepad.exe
TARGET_PNAME=$(shell .\\notdir.cmd $(TARGET_BIN))
TARGET_PID=$(shell .\\pgrep.cmd $(TARGET_PNAME))
PINTOOL_FILE=$(PINTOOL_NAME).dll
PIN_ROOT=..\\pin
PIN_EXE=$(PIN_ROOT)\\pin.exe
CWD=C:\\Users\\Stefano\\Desktop\\mepropin

TOOL_ROOTS := mepro
export TOOL_ROOTS

OBJECT_ROOTS := winapi
export OBJECT_ROOTS

# This defines any static libraries (archives), that need to be built.
LIBS := Dbghelp.lib
export LIBS


TARGET_BIN=C:\\Users\\Stefano\\Desktop\\repmove.exe

all: clean ia32 attach log  

ia32:
	$(MAKE) -f makefile.pin 'PIN_ROOT=$(PIN_ROOT)' TARGET=ia32

ia64:
	$(MAKE) -f makefile.pin 'PIN_ROOT=$(PIN_ROOT)'

clean:
	# Cleaning for ia32
	$(MAKE) -f makefile.pin clean 'PIN_ROOT=$(PIN_ROOT)' TARGET=ia32 TRACE=$(TRACE)
	# Cleaning for ia64
	$(MAKE) -f makefile.pin clean 'PIN_ROOT=$(PIN_ROOT)'

attach:
	@echo BINARY $(TARGET_BIN)
	@echo PNAME  $(TARGET_PNAME)
	@echo PID    $(TARGET_PID)
	$(PIN_EXE) -xyzzy -mesgon warning -pid $(TARGET_PID) -t $(CWD)\\obj-ia32\\$(PINTOOL_FILE)

exec:
	@echo BINARY $(TARGET_BIN)
	@echo PNAME  $(TARGET_PNAME)
	@echo PID    $(TARGET_PID)
	$(PIN_EXE) -xyzzy -mesgon warning -follow_execv -t $(CWD)\\obj-ia32\\$(PINTOOL_FILE) -- $(TARGET_BIN)

log: 
	cat pinatrace.out


