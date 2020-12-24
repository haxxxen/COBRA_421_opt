@echo off
cls

set PS3SDK=/c/PSDK3v2
set PS3DEV=/c/PSDK3v2/ps3dev2
set WIN_PS3SDK=C:/PSDK3v2
set PATH=%WIN_PS3SDK%/mingw/msys/1.0/bin;%WIN_PS3SDK%/mingw/bin;%PS3DEV%/ppu/bin;

REM if exist BIN rmdir BIN
if exist BIN\debug rm -fr BIN\debug\*.*>nul
if exist BIN\release rm -fr BIN\release\*.*>nul
if exist BIN\debug rm -fr BIN\debug
if exist BIN\release rm -fr BIN\release
if exist BIN rm -fr BIN

REM cd stage0_base
REM make -f stage0_base/Makefile clean
REM cd..
REM cd stage0_file
make -f stage0_file/Makefile clean
REM cd..
REM cd stage1_file
make -f stage1_file/Makefile clean
REM cd..
REM cd stage2
REM make -f stage2/Makefile_c clean
make -f stage2/Makefile_m clean

REM pause