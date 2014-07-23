@echo off
set x=-1
for /F "tokens=1,2" %%i in ('tasklist') do (
	if "%%i" equ "%1" (set x=%%j)
)
echo %x%