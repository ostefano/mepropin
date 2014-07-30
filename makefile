UNAME=$(shell uname)
PINTOOL_NAME=mepro


##### LINUX
#ATTACH_TO_TARGET=false
#TARGET_BIN=/bin/ls
#TARGET_PNAME := $(notdir $(TARGET_BIN))
#TARGET_PID := $(shell pgrep $(TARGET_PNAME))
#PINTOOL_FILE=$(PINTOOL_NAME).so
#PIN_EXE=$(PIN_ROOT)\\pin.exe


##### OSX
#ATTACH_TO_TARGET=false
#TARGET_BIN=/bin/ls
#TARGET_PNAME := $(notdir $(TARGET_BIN))
#TARGET_PID := $(shell pgrep $(TARGET_PNAME))
#PINTOOL_FILE=$(PINTOOL_NAME).dylib
#PIN_ROOT=/Users/stefano/pin-2.13-62732-clang.5.0-mac
#PIN_ROOT=/Users/stefano/pin-2.13-65163-clang.5.0-mac
#PIN_EXE=$(PIN_ROOT)\\pin.exe

#####  WINDOWS
ATTACH_TO_TARGET=true
TARGET_BIN=C:\\Windows\\SysWOW64\\notepad.exe
TARGET_PNAME=$(shell .\\notdir.cmd $(TARGET_BIN))
TARGET_PID=$(shell .\\pgrep.cmd $(TARGET_PNAME))
PINTOOL_FILE=$(PINTOOL_NAME).dll
PIN_ROOT=..\\pin
PIN_EXE=$(PIN_ROOT)\\pin.exe
CWD=C:\\Users\\Stefano\\Desktop\\mepropin



# We need the actual lib ncame based on arch
#ifeq ($(UNAME),Darwin)
#PINTOOL_FILE=$(PINTOOL_NAME).dylib
#else ifeq ()
#PINTOOL_FILE=$(PINTOOL_NAME).so
#endif

# This defines tests which run tools of the same name.  This is simply for convenience to avoid
# defining the test name twice (once in TOOL_ROOTS and again in TEST_ROOTS).
# Tests defined here should not be defined in TOOL_ROOTS and TEST_ROOTS.
#TEST_TOOL_ROOTS := 
#export TEST_TOOL_ROOTS

# This defines the tests to be run that were not already defined in TEST_TOOL_ROOTS.
#TEST_ROOTS :=
#export TEST_ROOTS

# This defines a list of tests that should run in the "short" sanity. Tests in this list must also
# appear either in the TEST_TOOL_ROOTS or the TEST_ROOTS list.
#SANITY_SUBSET := 
#export SANITY_SUBSET

# This defines the tools which will be run during the the tests, and were not already defined in
# TEST_TOOL_ROOTS.
TOOL_ROOTS := mepro
export TOOL_ROOTS

# This defines all the applications that will be run during the tests.
#APP_ROOTS := 
#export APP_ROOTS

# This defines any additional object files that need to be compiled.
OBJECT_ROOTS := winapi
export OBJECT_ROOTS

# This defines any additional dlls (shared objects), other than the pintools, that need to be compiled.
DLL_ROOTS :=
export DLL_ROOTS

# This defines any static libraries (archives), that need to be built.
LIB_ROOTS :=
export LIB_ROOTS

all: ia32

ia32:
	$(MAKE) -f makefile.pin 'PIN_ROOT=$(PIN_ROOT)' TARGET=ia32

ia64:
	$(MAKE) -f makefile.pin 'PIN_ROOT=$(PIN_ROOT)'

clean:
	# Cleaning for ia32
	$(MAKE) -f makefile.pin clean 'PIN_ROOT=$(PIN_ROOT)' TARGET=ia32
	# Cleaning for ia64
	$(MAKE) -f makefile.pin clean 'PIN_ROOT=$(PIN_ROOT)'

run:
ifeq ($(TARGET_CPU), x86)
	# x86
endif
	@echo B $(TARGET_BIN)
	@echo T $(TARGET_PNAME)
	@echo P $(TARGET_PID)

ifeq ($(ATTACH_TO_TARGET),true)
	$(PIN_EXE) -xyzzy -mesgon warning -pid $(TARGET_PID) -t $(CWD)\\obj-ia32\\$(PINTOOL_FILE)
else
	$(PIN_EXE) -xyzzy -mesgon warning -follow_execv -t $(CWD)\\obj-ia32\\$(PINTOOL_FILE) -- $(TARGET_BIN)
endif
