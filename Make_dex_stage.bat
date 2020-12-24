@echo off
cls

set PS3SDK=/c/PSDK3v2
set PS3DEV=%PS3SDK%/ps3dev2
set WIN_PS3SDK=C:/PSDK3v2
set PATH=%WIN_PS3SDK%/mingw/msys/1.0/bin;%WIN_PS3SDK%/mingw/bin;%PS3DEV%/ppu/bin;

if exist COBRA_RELEASE rm -fr COBRA_RELEASE/*.cex>nul
if exist COBRA_RELEASE rm -fr COBRA_RELEASE/*.dex>nul
if exist _PUP rm -fr _PUP/*.bak>nul
if exist *.cex rm -fr *.cex>nul
if exist *.dex rm -fr *.dex>nul

REM make -f stage2\Makefile_st2mCd.mak all
make -f stage2\Makefile_st2mDd.mak all

REM if exist stage2.cexr (
	REM if not exist COBRA_RELEASE mkdir COBRA_RELEASE
)
REM if not exist COBRA_DEBUG mkdir COBRA_DEBUG
REM if not exist _PUP mkdir _PUP

REM if exist stage2.cexr	move  stage2.cexr	COBRA_RELEASE/stage2.cex>nul
REM if exist stage2.cex     move  stage2.cex	stage2.cex>nul
REM if exist stage2.dexr	move  stage2.dexr	COBRA_RELEASE/stage2.dex>nul
REM if exist stage2.dex     move  stage2.dex	stage2.dex>nul
REM cp stage2.cex stage2.cex.bak>nul
REM cp stage2.dex stage2.dex.bak>nul
REM move  stage2.cex.bak	_PUP/stage2.cex.bak>nul
REM move  stage2.dex.bak	_PUP/stage2.dex.bak>nul

pause
