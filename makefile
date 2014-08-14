UNAME=$(shell uname)
PINTOOL_NAME=mepro

#REMEMBER. CANT USE ABSOLUTE PATH BECAUSE CYGWIN CANT CANONALUZE COLONS

#####  WINDOWS
ATTACH_TO_TARGET=true
TARGET_BIN=C:\\Windows\\SysWOW64\\notepad.exe
TARGET_PNAME=$(shell .\\notdir.cmd $(TARGET_BIN))
TARGET_PID=$(shell .\\pgrep.cmd $(TARGET_PNAME))
PINTOOL_FILE=$(PINTOOL_NAME).dll
PIN_ROOT=..\\pin
PIN_ROOT_ABS=C:\\Users\\Stefano\\pin\\
PIN_EXE=$(PIN_ROOT)\\pin.exe
CWD=C:\\Users\\Stefano\\mepropin

TOOL_ROOTS := mepro
export TOOL_ROOTS

OBJECT_ROOTS := winapi classifier
export OBJECT_ROOTS

TARGET_BIN=C:\\Users\\Stefano\\mepropin\\test\\repmove.exe
TARGET_BIN=C:\\Program\ Files\ \(x86\)\\Mozilla\ Firefox\\firefox.exe
TARGET_BIN=C:\\Users\\Stefano\\mepropin\\test\\fork.exe
#TARGET_BIN=C:\\Windows\\SysWOW64\\notepad.exe

all: clean ia32 exec log  

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
	$(PIN_EXE) -xyzzy -mesgon warning -pid $(TARGET_PID) -t $(CWD)\\obj-ia32\\$(PINTOOL_FILE) -pin_path $(PIN_ROOT_ABS) -tool_path $(CWD)\\obj-ia32\\ -tool_name $(PINTOOL_FILE) -first_process 1

exec:
	@echo BINARY $(TARGET_BIN)
	@echo PNAME  $(TARGET_PNAME)
	@echo PID    $(TARGET_PID)
	$(PIN_EXE) -xyzzy -mesgon warning -follow_execv -t $(CWD)\\obj-ia32\\$(PINTOOL_FILE) -pin_path $(PIN_ROOT_ABS) -tool_path $(CWD)\\obj-ia32\\ -tool_name $(PINTOOL_FILE) -first_process 1 -- $(TARGET_BIN)

log: 
	cat pinatrace.out


