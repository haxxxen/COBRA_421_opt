#include <stddef.h>

#include <lv2/lv2.h>
#include <lv2/syscall.h>
#include <lv2/memory.h>
#include <lv2/io.h>
#include <lv2/libc.h>
#include <lv2/thread.h>
#include <lv2/patch.h>
#include <lv2/security.h>

#include <lv1/lv1.h>
#include <lv1/patch.h>

#ifdef DEBUG
#include <debug.h>
#define DPRINTF		_debug_printf
#define DPRINT_HEX	debug_print_hex
#else
#include <debug.h>
#define DPRINTF(...)
#define DPRINT_HEX(a, b)
#endif
#if defined(CEX_KERNEL)
#define STAGE2_FILE	"/dev_rebug/rebug/cobra/stage2.cex"
#endif
#if defined(DEX_KERNEL)
#define STAGE2_FILE	"/dev_rebug/rebug/cobra/stage2.dex"
#endif
#ifdef MOUNT		
#define PRINT_FILE	"/dev_rebug/eprint"
void tty_write_clone(void);
void flash_mount_clone(void);
#define CB_LOCATION_CEX "/dev_rebug/rebug/cobra/stage2.cex"
#define CB_LOCATION_DEX "/dev_rebug/rebug/cobra/stage2.dex"
#define SA_LOCATION "/dev_rebug/sys/internal/sys_audio.sprx"
#define SP_LOCATION "/dev_rebug/sys/internal/sys_plugin.sprx"
#define SM_LOCATION "/dev_rebug/sys/internal/sys_sm.sprx"
#define FLAG_FILE	"/dev_usb000/nocobra"
#define YES "OK"
#define NO "FAILED"
uint8_t tmp[6];
		if (cellFsStat(FLAG_FILE, &stat) == 0)
		{
			DPRINTF("COBRA :::: '%s' Flag File detected. Disable stage2: ", FLAG_FILE);
			if (cellFsRename(CB_LOCATION_CEX, CB_LOCATION_CEX".bak") == 0){
				if(cellFsRename(CB_LOCATION_DEX, CB_LOCATION_DEX".bak") == 0){
					if(cellFsRename(SA_LOCATION, SP_LOCATION) == 0){
						if(cellFsRename(SM_LOCATION, SA_LOCATION) == 0) int off = 1;
					}
				}
			}
			sprintf((char*)tmp, "%s\n", off?(YES):(NO));
			DPRINTF((char*)tmp);
		}
#endif

int main(void)
{
	void *stage2 = NULL;
	f_desc_t f;
	int (* func)(void);	
	// int ret = 0;
	// int fd;
#ifdef DEBUG		
	debug_init();
	// debugk_install();
#if defined(CEX_KERNEL)
	DPRINTF("COBRA :::: CEX stage1 says hello.\n");	
#elif defined(DEX_KERNEL)
	DPRINTF("COBRA :::: DEX stage1 says hello.\n");	
#endif
#endif
	int ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1", "CELL_FS_FAT", "/dev_rebug", 0, 0, 0, 0, 0);
/* #ifdef EDUMP		
	uint32_t offset;
	uint8_t value;
	CellFsStat stat;
	if (cellFsStat(FLAG_FILE, &stat) == 0)
	{
		DPRINTF("COBRA :::: Flash mounted\n");
		DPRINTF("COBRA :::: Found '%s' Flag File, dumping EEPROM Content\n", FLAG_FILE);
		for (offset = 0x2F28; offset < 0x03100; offset ++){
			update_mgr_read_eeprom(offset, &value, UM_AUTH_ID);
			// DPRINT_HEX(&value, 1);
			DPRINTF("%02X", value);
		}
		for (offset = 0x48000; offset < 0x48100; offset++){
		// for (offset = 0x48000; offset < 0x48E00; offset++){
			update_mgr_read_eeprom(offset, &value, UM_AUTH_ID);
			// DPRINT_HEX(&value, 1);
			DPRINTF("%02X", value);
		}
		for (offset = 0x48800; offset < 0x48900; offset++){
			update_mgr_read_eeprom(offset, &value, UM_AUTH_ID);
			// DPRINT_HEX(&value, 1);
			DPRINTF("%02X", value);
		}
		for (offset = 0x48C00; offset < 0x48E00; offset++){
			update_mgr_read_eeprom(offset, &value, UM_AUTH_ID);
			// DPRINT_HEX(&value, 1);
			DPRINTF("%02X", value);
		}
		DPRINTF("\nCOBRA :::: Finished. Booting System\n");
	}
#endif */
	if(ret == 0)
	{
		DPRINTF("COBRA :::: Flash mounted\n");
		CellFsStat stat;
#ifdef EDUMP		
		uint32_t offset;
		uint8_t value;
		if (cellFsStat(PRINT_FILE, &stat) == 0)
		{
			DPRINTF("COBRA :::: '%s' Flag File detected. Dumping EEPROM...\n", PRINT_FILE);
			for (offset = 0x2F00; offset < 0x03100; offset ++) {
				update_mgr_read_eeprom(offset, &value, UM_AUTH_ID);
				// DPRINT_HEX(&value, 1);
				DPRINTF("%02X", value);
			}
			for (offset = 0x48000; offset < 0x48100; offset++) {
			// for (offset = 0x48000; offset < 0x48E00; offset++){
				update_mgr_read_eeprom(offset, &value, UM_AUTH_ID);
				// DPRINT_HEX(&value, 1);
				DPRINTF("%02X", value);
			}
			for (offset = 0x48800; offset < 0x48900; offset++) {
				update_mgr_read_eeprom(offset, &value, UM_AUTH_ID);
				// DPRINT_HEX(&value, 1);
				DPRINTF("%02X", value);
			}
			for (offset = 0x48C00; offset < 0x48E00; offset++) {
				update_mgr_read_eeprom(offset, &value, UM_AUTH_ID);
				// DPRINT_HEX(&value, 1);
				DPRINTF("%02X", value);
			}
			DPRINTF("\nCOBRA :::: ...Finished. Booting System\n");
		}
#endif
		if (cellFsStat(STAGE2_FILE, &stat) == 0)
		{
			int fd;
			if (cellFsOpen(STAGE2_FILE, CELL_FS_O_RDONLY, &fd, 0, NULL, 0) == 0)
			{
				uint32_t psize = stat.st_size;
#if defined(CEX_KERNEL)
				DPRINTF("COBRA :::: CEX Payload size = %d\n", psize);
#elif defined(DEX_KERNEL)
				DPRINTF("COBRA :::: DEX Payload size = %d\n", psize);
#endif
				stage2 = alloc(psize, 0x27);
				if (stage2)
				{
					uint64_t rs;
					if (cellFsRead(fd, stage2, psize, &rs) != 0)
					{
#if defined(CEX_KERNEL)
						DPRINTF("COBRA :::: CEX stage2 read fail.\n");
#elif defined(DEX_KERNEL)
						DPRINTF("COBRA :::: DEX stage2 read fail.\n");
#endif
						dealloc(stage2, 0x27);
						stage2 = NULL;
					}
				}
				else
#if defined(CEX_KERNEL)
					DPRINTF("COBRA :::: Cannot allocate CEX stage2\n");
#elif defined(DEX_KERNEL)
					DPRINTF("COBRA :::: Cannot allocate DEX stage2\n");
#endif
				cellFsClose(fd);
			}
		}
		else
#if defined(CEX_KERNEL)
			DPRINTF("COBRA :::: There is no CEX stage2, booting system.\n");
#elif defined(DEX_KERNEL)
			DPRINTF("COBRA :::: There is no DEX stage2, booting system.\n");
#endif
	}
	if (stage2)
	{
		f.toc = (void *)MKA(TOC);
		f.addr = stage2;			
		func = (void *)&f;	
#if defined(CEX_KERNEL)
		DPRINTF("COBRA :::: Calling CEX stage2...\n");
#elif defined(DEX_KERNEL)
		DPRINTF("COBRA :::: Calling DEX stage2...\n");
#endif
		func();
	}
	return ret;
}

