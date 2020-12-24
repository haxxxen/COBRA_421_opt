@echo off
cls

set PS3SDK=/c/PSDK3v2
set PS3DEV=/c/PSDK3v2/ps3dev2
set WIN_PS3SDK=C:/PSDK3v2
set PATH=%WIN_PS3SDK%/mingw/msys/1.0/bin;%WIN_PS3SDK%/mingw/bin;%PS3DEV%/ppu/bin;%SCETOOL%;
set SCETOOL=C:\PSDK3v2\ps3dev2\bin

REM cd stage0_base
REM make -f Makefile all
REM cd..
cd stage0_file
make -f Makefile all
cd..
cd stage1_file
make -f Makefile_421D_dbg all
REM make -f Makefile all

REM if exist *r.self move *r.self BIN\release>nul
REM if exist *d.self move *d.self BIN\debug>nul
if exist lv2Ckerneld.self move lv2Ckerneld.self ../lv2Ckernel.self>nul
REM if exist lv2Ckernelr.self move lv2Ckernelr.self ../lv2Ckernelr.self>nul
if exist lv2_kerneld.self move lv2_kerneld.self ../lv2_kernel.self>nul
REM if exist lv2_kernelr.self cp lv2_kernelr.self ../lv2_kernelr.self>nul

REM if exist lv2Ckerneld.self move lv2Ckerneld.self BIN\debug\lv2Ckernel.self>nul
REM if exist lv2Ckernelr.self move lv2Ckernelr.self BIN\release\lv2Ckernel.self>nul
REM if exist lv2_kerneld.self move lv2_kerneld.self BIN\debug\lv2_kernel.self>nul
REM if exist lv2_kernelr.self move lv2_kernelr.self BIN\release\lv2_kernel.self>nul

REM move BIN ../
REM cp -r BIN ../../
REM rm -rf BIN
cd..

REM cd stage0_base
REM make -f Makefile clean
REM cd..
cd stage0_file
make -f Makefile clean
cd..
cd stage1_file
make -f Makefile clean
REM cd..
REM cd stage2
REM make -f Makefile clean
pause