CC				:= ppu-gcc
CXX				:= ppu-g++
LD				:= ppu-ld 
OBJCOPY			:= ppu-objcopy
OBJDUMP			:= ppu-objdump
AR 				:= ppu-ar
STRIP			:= ppu-strip
INCLUDE			= stage2/include lv2/include lv1/include cryptcode/include debug/include
INCLUDE			+= $(PS3DEV)/ppu/ppu/include
LIBSDIR         =
LIBS           	=
BUILD_TYPE     	= debug


CFLAGS = -ffunction-sections -fdata-sections -Os -m64 -fno-builtin -fno-exceptions \
			   -Os -Wall -Wno-strict-aliasing -Wno-multichar $(foreach dir,$(INCLUDE),-I$(dir)) \
			   -DLV2 -DCEX_KERNEL -DFIRMWARE_4_21 -DCFW -DUSE_LV1_PEEK_POKE -DPS3MAPI -DBC -ffreestanding 
CFLAGS += --std=gnu99
 # -DSC40
ifeq ($(BUILD_TYPE), debug)
CFLAGS += -DDEBUG -DTEST 
endif

ifeq ($(BUILD_TYPE), ps2_debug)
CFLAGS += -DDEBUG -DPS2EMU_DEBUG -DTEST
endif

ifeq ($(BUILD_TYPE), test)
CFLAGS += -DTEST
endif

#CFLAGS += -DPSN_SUPPORT -DPAY -DSC15 -DSC8


#LDFLAGS= -T stage2.ld -nostartfiles -nostdlib -nodefaultlibs -Wl,-static -Wl,-s -L. $(foreach dir,$(LIBSDIR),-L$(dir)) $(LIBS) \
#	-Wl,--gc-sections -Wl,-Map=stage2.map
LDFLAGS= -T stage2/stage2.ld -nostartfiles -nostdlib -nodefaultlibs -Wl,-static -L. $(foreach dir,$(LIBSDIR),-L$(dir)) $(LIBS) \
	 -Wl,--gc-sections -Wl,-Map=stage2/stage2.map

OBJS = stage2/start.o stage2/ps3mapi_core.o stage2/main.o stage2/crypto.o stage2/modulespatch.o stage2/psp_s.o stage2/mappath.o stage2/storage_ext.o stage2/psp.o stage2/permissions.o  \
	lv2/src/usb.o lv2/src/patch.o lv2/src/interrupt.o lv2/src/interrupt_c.o lv2/src/io.o lv2/src/libc.o \
	lv2/src/libc_c.o lv2/src/memory.o lv2/src/memory_c.o lv2/src/thread.o lv2/src/thread_c.o lv2/src/process.o \
	lv2/src/synchronization.o lv2/src/modules.o lv2/src/modules_c.o lv2/src/storage.o lv2/src/object.o \
	lv2/src/security.o lv2/src/time.o lv2/src/hid.o lv2/src/pad.o lv2/src/syscall.o \
	lv1/src/hvcall.o lv1/src/stor.o lv1/src/device.o 

ifeq ($(BUILD_TYPE), debug)
OBJS += debug/src/debug.o debug/src/printf.o debug/src/debug_util.o
endif

ifeq ($(BUILD_TYPE), ps2_debug)
OBJS += stage2/laboratory.o debug/src/debug.o debug/src/printf.o debug/src/debug_util.o
endif

all: stage2.cex
	rm -f stage2/*.o *.elf stage2/*.map stage2/*.map *.map *.lzma lv2/src/*.o lv1/src/*.o debug/src/*.o

objdump: stage2.cex
	$(OBJDUMP) -D -EB -b binary -m powerpc:common64 stage2.cex

%.cex: %.elf
	$(OBJCOPY) -O binary $< $@	

stage2.elf: $(OBJS) stage2/stage2.ld
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.S
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.elf *.bin *.cex *.cexr stage2/*.elf stage2/*.bin stage2/*.o stage2/*.map *.lzma lv2/src/*.o lv1/src/*.o debug/src/*.o
