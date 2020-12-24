#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/interrupt.h>
#include <lv2/modules.h>
#include <lv2/process.h>
#include <lv2/memory.h>
#include <lv2/io.h>
#include <lv2/pad.h>
#include <lv2/symbols.h>
#include <lv2/patch.h>
#include <lv2/error.h>
#include <lv2/security.h>
#include <lv2/thread.h>
#include <lv2/syscall.h>
#include "common.h"
#include "modulespatch.h"
#include "permissions.h"
#include "crypto.h"
#include "storage_ext.h"
#include "psp.h"
#include "syscall8.h"
#include "self.h"
#include "mappath.h"
#include <lv1/patch.h>
// #include "cobra.h"
// #include "config.h"
#include <lv2/time.h>

#define DEFS
#ifdef DEFS
#define MAX_VSH_PLUGINS			7
// #define MAX_GAME_PLUGINS		5
#define BOOT_PLUGINS_FILE		"/dev_flash2/boot_plugins.txt"
#ifdef PAY
#define BOOT_PLUGINS_KERNEL_FILE			"/dev_flash2/boot_plugins_kernel.txt"
#define MAX_BOOT_PLUGINS_KERNEL			5
// #define GAME_PLUGINS_FILE		"/dev_hdd0/game_plugins.txt"
// #define GAME_PLUGINS_FIRST_SLOT		5
// #define MAX_START_PLUGINS 		(MAX_GAME_PLUGINS-GAME_PLUGINS_FIRST_SLOT)
#endif
#define BOOT_PLUGINS_FIRST_SLOT		1
#define MAX_BOOT_PLUGINS 		(MAX_VSH_PLUGINS-BOOT_PLUGINS_FIRST_SLOT)
// #define PRX_PATH			"/dev_flash3/artsMAN_ntfs.sprx"
#define PRX_GAME			"/dev_hdd0/tmp/MySPRX.sprx"
#define GAME_PLUGINS_FILE		"/dev_hdd0/sprx.txt"
// #define PRX_PATH			"/dev_flash3/artsMAN.sprx"
/* #define PRX_PATH			"/dev_flash/vsh/module/webMAN.sprx"
#define PRX_TEST			"/dev_flash/vsh/module/webMAN_test.sprx"
#define PRX_TEST			"/dev_hdd0/z/plugins/webMAN_test.sprx"
#define PRX_PATH			"/dev_flash/vsh/module/webftp_server.sprx" */
// #define DUMP_FILE	"/dev_hdd0/eeprom_dump.log"

// #define PS3MAPI
// #define CORE
// #define STEALTH
#endif /* DEFS */

#define N_SPRX_KEYS_1 (sizeof(sprx_keys_set1)/sizeof(KeySet))

KeySet sprx_keys_set1[] =
{
	{ 
		{ 
			0xD6, 0xFD, 0xD2, 0xB9, 0x2C, 0xCC, 0x04, 0xDD,
			0x77, 0x3C, 0x7C, 0x96, 0x09, 0x5D, 0x7A, 0x3B
		},

		0xBA2624B2B2AA7461ULL
	},
};

// Keyset for pspemu, and for future vsh plugins or whatever is added later
#define N_SPRX_KEYS_2 (sizeof(sprx_keys_set2)/sizeof(KeySet))

KeySet sprx_keys_set2[] =
{
	{
		{
			0x7A, 0x9E, 0x0F, 0x7C, 0xE3, 0xFB, 0x0C, 0x09, 
			0x4D, 0xE9, 0x6A, 0xEB, 0xA2, 0xBD, 0xF7, 0x7B
		},

		0x8F8FEBA931AF6A19ULL
	},
	
	{
		{
			0xDB, 0x54, 0x44, 0xB3, 0xC6, 0x27, 0x82, 0xB6, 
			0x64, 0x36, 0x3E, 0xFF, 0x58, 0x20, 0xD9, 0x83
		},

		0xE13E0D15EF55C307ULL
	},
};

static uint8_t *saved_buf;
static void *saved_sce_hdr;
static uint32_t caller_process = 0;

process_t vsh_process, dbg_process, game_process, emer_process, emu1_process, netemu1_process, netemu2_process, osd_process;

uint8_t flag, safe_mode, up_mode, tmp[6], txt[55], condition_ps2softemu = 0, condition_apphome = 0, condition_psp_iso = 0, condition_psp_dec = 0, condition_psp_keys = 0, condition_psp_prometheus = 0, condition_vsh_check = 1, condition_net_psxemu = 0, condition_psx_psxemu = 0, condition_pemucorelib = 1, condition_rsod = 1, condition_amg = 1, condition_psp_change_emu = 0, condition_game = 1, toggle = 0, condition_psxemu = 1;
uint64_t vsh_check;
// uint8_t condition_disable_gameupdate = 0, block_peek = 0; // Disabled

// Plugins
sys_prx_id_t vsh_plugins[MAX_VSH_PLUGINS], sys_plugins[50], game_plugins[5];
static int loading_plugin;

CellFsStat stat;
int on = 0, off = 0, sys_mode = 0/* , debug = 0, sysaudio = 0, sman = 0, app = 0, arts = 0, xmb = 0, vsh = 0, game = 0, loading_sys_plugin */;
// pad_data data;

LV2_EXPORT int decrypt_func(uint64_t *, uint32_t *);

#if defined(SPRX)
#if defined(CEX_KERNEL)
static uint8_t condition_true = 1;
SprxPatch vsh_patches[] =
{
	{ elf1_func1 + elf1_func1_offset, LI(R3, 1), &condition_true },
	{ elf1_func1 + elf1_func1_offset + 4, BLR, &condition_true },
	{ elf1_func2 + elf1_func2_offset, NOP, &condition_true },
	// { game_update_offset, LI(R3, -1), &condition_disable_gameupdate }, 
	// { ps2tonet_patch, ORI(R3, R3, 0x8204), &condition_ps2softemu },
	// { ps2tonet_size_patch, LI(R5, 0x40), &condition_ps2softemu },
	{ 0 }
};

SprxPatch cex_vsh_patches[] =
{
	{ cex_elf1_func1 + cex_elf1_func1_offset, LI(R3, 1), &condition_true },
	{ cex_elf1_func1 + cex_elf1_func1_offset + 4, BLR, &condition_true },
	{ cex_elf1_func2 + cex_elf1_func2_offset, NOP, &condition_true },
	// { game_update_offset, LI(R3, -1), &condition_disable_gameupdate }, 
	// { ps2tonet_patch, ORI(R3, R3, 0x8204), &condition_ps2softemu },
	// { ps2tonet_size_patch, LI(R5, 0x40), &condition_ps2softemu },
	{ 0 }
};
#endif

SprxPatch basic_plugins_patches[] =
{
	//{ ps1emu_type_check_offset, NOP, &condition_true }, // Changes ps1_emu.self to ps1_netemu.self (DISABLED)
	// { rsod_check_offset, B(rsod_check_offset_2), &condition_true }, // apply RSOD bypass
	// { rsod_check_offset, MAKE_JUMP_VALUE(rsod_check_offset_1, rsod_check_offset_2), &condition_true }, // apply RSOD bypass
	{ 0 }
};

SprxPatch nas_plugin_patches[] =
{
	// { elf2_func1 + elf2_func1_offset, NOP, &condition_true },
	// { geohot_pkg_offset, LI(R0, 0), &condition_true },
	{ 0 }
};

SprxPatch explore_plugin_patches[] =
{
	// { app_home_offset, 0x2f646576, &condition_apphome },
	// { app_home_offset+4, 0x5f626476, &condition_apphome },
	// { app_home_offset+8, 0x642f5053, &condition_apphome }, 
	// { ps2_nonbw_offset, LI(0, 1), &condition_ps2softemu },
	{ 0 }
};

SprxPatch explore_category_game_patches[] =
{
	// { ps2_nonbw_offset2, LI(R0, 1), &condition_ps2softemu },
	// { unk_patch_offset1, NOP, &condition_true },
	// { unk_patch_offset2, NOP, &condition_true },
	{ 0 }
};

SprxPatch bdp_disc_check_plugin_patches[] =
{
	// { dvd_video_region_check_offset, LI(R3, 1), &condition_true }, // Kills standard dvd-video region protection (not RCE one) //
	{ 0 }
};

SprxPatch ps1_emu_patches[] =
{
	// { ps1_emu_get_region_offset, LI(R29, 0x82), &condition_true }, // regions 0x80-0x82 bypass region check. //
	{ 0 }
};

SprxPatch ps1_netemu_patches[] =
{
	// Some rare titles such as Langrisser Final Edition are launched through ps1_netemu!
	// { ps1_netemu_get_region_offset, LI(R3, 0x82), &condition_true }, 
	{ 0 }
};

SprxPatch game_ext_plugin_patches[] =
{
	// { sfo_check_offset, NOP, &condition_true }, 
	// { ps2_nonbw_offset3, LI(R0, 1), &condition_ps2softemu },
	// { ps_region_error_offset, NOP, &condition_true }, // Needed sometimes... //	
	// { ps_video_error_offset, LI(R3,0), &condition_true }, // Disable the check for video setting //
	// { ps_video_error_offset+4, BLR, &condition_true },
	{ 0 }
};

SprxPatch psp_emulator_patches[] =
{
	// Sets psp mode as opossed to minis mode. Increases compatibility, removes text protection and makes most savedata work
	// { psp_set_psp_mode_offset, LI(R4, 0), &condition_psp_iso },
	{ 0 }
};

SprxPatch libsysutil_savedata_psp_patches[] =
{
#ifdef FIRMWARE_3_55
	{ psp_savedata_patch1, MAKE_JUMP_VALUE(psp_savedata_patch1, psp_savedata_patch2), &condition_psp_iso },
	{ psp_savedata_patch3, NOP, &condition_psp_iso },
	{ psp_savedata_patch4, NOP, &condition_psp_iso },
	{ psp_savedata_patch5, NOP, &condition_psp_iso },
	{ psp_savedata_patch6, NOP, &condition_psp_iso },
	{ psp_savedata_patch7, NOP, &condition_psp_iso },
#elif defined(FIRMWARE_4_21) || defined(FIRMWARE_4_30) || defined(FIRMWARE_4_46)
	{ psp_savedata_patch1, MAKE_JUMP_VALUE(psp_savedata_patch1, psp_savedata_patch2), &condition_psp_iso },
	// { psp_savedata_patch3, NOP, &condition_psp_iso },
	// { psp_savedata_patch4, NOP, &condition_psp_iso },
	// { psp_savedata_patch5, NOP, &condition_psp_iso },
	// { psp_savedata_patch6, NOP, &condition_psp_iso },	
#endif
	{ 0 }
};
#endif

SprxPatch emulator_api_patches[] =
{
	// Read umd patches
	{ psp_read, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp_read+4, MFLR(R0), &condition_psp_iso },
	{ psp_read+8, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_read+0x0C, MR(R8, R7), &condition_psp_iso },
	{ psp_read+0x10, MR(R7, R6), &condition_psp_iso },
	{ psp_read+0x14, MR(R6, R5), &condition_psp_iso },
	{ psp_read+0x18, MR(R5, R4), &condition_psp_iso },
	{ psp_read+0x1C, MR(R4, R3), &condition_psp_iso },
	{ psp_read+0x20, LI(R3, SYSCALL8_OPCODE_READ_PSP_UMD), &condition_psp_iso },	
	{ psp_read+0x24, LI(R11, 0xB), &condition_psp_iso },
	{ psp_read+0x28, SC, &condition_psp_iso },
	{ psp_read+0x2C, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_read+0x30, MTLR(R0), &condition_psp_iso },
	{ psp_read+0x34, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp_read+0x38, BLR, &condition_psp_iso },
	// Read header patches
	{ psp_read+0x3C, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp_read+0x40, MFLR(R0), &condition_psp_iso },
	{ psp_read+0x44, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_read+0x48, MR(R7, R6), &condition_psp_iso },
	{ psp_read+0x4C, MR(R6, R5), &condition_psp_iso },
	{ psp_read+0x50, MR(R5, R4), &condition_psp_iso },
	{ psp_read+0x54, MR(R4, R3), &condition_psp_iso },
	{ psp_read+0x58, LI(R3, SYSCALL8_OPCODE_READ_PSP_HEADER), &condition_psp_iso },	
	{ psp_read+0x5C, LI(R11, 0xB), &condition_psp_iso },
	{ psp_read+0x60, SC, &condition_psp_iso },
	{ psp_read+0x64, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_read+0x68, MTLR(R0), &condition_psp_iso },
	{ psp_read+0x6C, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp_read+0x70, BLR, &condition_psp_iso },
	{ psp_read_header, MAKE_CALL_VALUE(psp_read_header, psp_read+0x3C), &condition_psp_iso },
#ifdef FIRMWARE_3_55
	// Drm patches
	{ psp_drm_patch5, MAKE_JUMP_VALUE(psp_drm_patch5, psp_drm_patch6), &condition_psp_iso },
	{ psp_drm_patch7, LI(R6, 0), &condition_psp_iso },
	{ psp_drm_patch8, LI(R7, 0), &condition_psp_iso },
	{ psp_drm_patch9, MAKE_JUMP_VALUE(psp_drm_patch9, psp_drm_patch10), &condition_psp_iso },
	{ psp_drm_patch11, LI(R6, 0), &condition_psp_iso },
	{ psp_drm_patch12, LI(R7, 0), &condition_psp_iso },
	// product id
	{ psp_product_id_patch1, MAKE_JUMP_VALUE(psp_product_id_patch1, psp_product_id_patch2), &condition_psp_iso },
	{ psp_product_id_patch3, MAKE_JUMP_VALUE(psp_product_id_patch3, psp_product_id_patch4), &condition_psp_iso },		
#endif
#if defined (FIRMWARE_4_21) || defined(FIRMWARE_4_30) || defined (FIRMWARE_4_46)
	// Drm patches
	{ psp_drm_patch5, MAKE_JUMP_VALUE(psp_drm_patch5, psp_drm_patch6), &condition_psp_iso },
	{ psp_drm_patch7, LI(R6, 0), &condition_psp_iso },
	{ psp_drm_patch8, LI(R7, 0), &condition_psp_iso },
	{ psp_drm_patch9, NOP, &condition_psp_iso },
	{ psp_drm_patch11, LI(R6, 0), &condition_psp_iso },
	{ psp_drm_patch12, LI(R7, 0), &condition_psp_iso },
	// product id
	{ psp_product_id_patch1, NOP, &condition_psp_iso },
	{ psp_product_id_patch3, NOP, &condition_psp_iso },	
#endif
	{ 0 }
};

SprxPatch pemucorelib_patches[] =
{
/* #ifdef FIRMWARE_3_55
#ifdef DEBUG
	{ psp_debug_patch, LI(R3, SYSCALL8_OPCODE_PSP_SONY_BUG), &condition_psp_iso },
	{ psp_debug_patch+4, LI(R11, 0xB), &condition_psp_iso },
	{ psp_debug_patch+8, SC, &condition_psp_iso },
#endif	
#endif */
/* #if defined(FIRMWARE_4_21)
#ifdef DEBUG
	{ psp_debug_patch, LI(R3, SYSCALL8_OPCODE_PSP_SONY_BUG), &condition_psp_iso },
	{ psp_debug_patch+4, LI(R11, 0xB), &condition_psp_iso },
	{ psp_debug_patch+8, SC, &condition_psp_iso },
#endif
#endif */
	{ psp_eboot_dec_patch, LI(R6, 0x110), &condition_psp_dec }, // -> makes unsigned psp eboot.bin run, 0x10 works too
	{ psp_prx_patch, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp_prx_patch+4, MFLR(R6), &condition_psp_iso },
	{ psp_prx_patch+8, STD(R6, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x0C, LI(R11, 0xB), &condition_psp_iso },
	{ psp_prx_patch+0x10, MR(R5, R4), &condition_psp_iso },
	{ psp_prx_patch+0x14, MR(R4, R3), &condition_psp_iso },
	{ psp_prx_patch+0x18, LI(R3, SYSCALL8_OPCODE_PSP_PRX_PATCH), &condition_psp_iso },
	{ psp_prx_patch+0x1C, SC, &condition_psp_iso },
	{ psp_prx_patch+0x20, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x24, MTLR(R0), &condition_psp_iso },
	{ psp_prx_patch+0x28, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp_prx_patch+0x2C, BLR, &condition_psp_iso },	
	// Patch for savedata binding
	{ psp_savedata_bind_patch1, MR(R5, R19), &condition_psp_iso },
	{ psp_savedata_bind_patch2, MAKE_JUMP_VALUE(psp_savedata_bind_patch2, psp_prx_patch+0x30), &condition_psp_iso },
	{ psp_prx_patch+0x30, LD(R19, 0xFF98, SP), &condition_psp_iso },
	{ psp_prx_patch+0x34, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp_prx_patch+0x38, MFLR(R0), &condition_psp_iso },
	{ psp_prx_patch+0x3C, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x40, LI(R11, 0xB), &condition_psp_iso },
	{ psp_prx_patch+0x44, MR(R4, R3), &condition_psp_iso },
	{ psp_prx_patch+0x48, LI(R3, SYSCALL8_OPCODE_PSP_POST_SAVEDATA_INITSTART), &condition_psp_iso },
	{ psp_prx_patch+0x4C, SC, &condition_psp_iso },
	{ psp_prx_patch+0x50, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x54, MTLR(R0), &condition_psp_iso },
	{ psp_prx_patch+0x58, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp_prx_patch+0x5C, BLR, &condition_psp_iso },
	{ psp_savedata_bind_patch3, MAKE_JUMP_VALUE(psp_savedata_bind_patch3, psp_prx_patch+0x60), &condition_psp_iso },
	{ psp_prx_patch+0x60, STDU(SP, 0xFF90, SP), &condition_psp_iso },
	{ psp_prx_patch+0x64, MFLR(R0), &condition_psp_iso },
	{ psp_prx_patch+0x68, STD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x6C, LI(R11, 0xB), &condition_psp_iso },
	{ psp_prx_patch+0x70, LI(R3, SYSCALL8_OPCODE_PSP_POST_SAVEDATA_SHUTDOWNSTART), &condition_psp_iso },
	{ psp_prx_patch+0x74, SC, &condition_psp_iso },
	{ psp_prx_patch+0x78, LD(R0, 0x80, SP), &condition_psp_iso },
	{ psp_prx_patch+0x7C, MTLR(R0), &condition_psp_iso },
	{ psp_prx_patch+0x80, ADDI(SP, SP, 0x70), &condition_psp_iso },
	{ psp_prx_patch+0x84, BLR, &condition_psp_iso },
	// Prometheus
	{ psp_prometheus_patch, '.OLD', &condition_psp_prometheus },
/* #if defined(FIRMWARE_4_21) || defined(FIRMWARE_4_30) || defined(FIRMWARE_4_46)
	// Extra save data patch required since some 3.60+ firmware
	{ psp_extra_savedata_patch, LI(R31, 1), &condition_psp_iso },
#endif */
	{ 0 }
};

SprxPatch libfs_external_patches[] =
{
	// Redirect internal libfs function to kernel. If condition_apphome is 1, it means there is a JB game mounted
	{ aio_copy_root_offset, STDU(SP, 0xFF90, SP), &condition_apphome },
	{ aio_copy_root_offset+4, MFLR(R0), &condition_apphome },
	{ aio_copy_root_offset+8, STD(R0, 0x80, SP), &condition_apphome },
	{ aio_copy_root_offset+0x0C, MR(R5, R4), &condition_apphome },
	{ aio_copy_root_offset+0x10, MR(R4, R3), &condition_apphome },
	{ aio_copy_root_offset+0x14, LI(R3, SYSCALL8_OPCODE_AIO_COPY_ROOT), &condition_apphome },
	{ aio_copy_root_offset+0x18, LI(R11, 0xB), &condition_apphome },
	{ aio_copy_root_offset+0x1C, SC, &condition_apphome },
	{ aio_copy_root_offset+0x20, LD(R0, 0x80, SP), &condition_apphome },
	{ aio_copy_root_offset+0x24, MTLR(R0), &condition_apphome },
	{ aio_copy_root_offset+0x28, ADDI(SP, SP, 0x70), &condition_apphome },
	{ aio_copy_root_offset+0x2C, BLR, &condition_apphome },
	{ 0 }
};

PatchTableEntry patch_table[] =
{
#if defined(SPRX)
#if defined(CEX_KERNEL)
	{ VSH_HASH, vsh_patches },
	{ VSH_NRM_HASH, vsh_patches },
	{ VSH_CEX_HASH, cex_vsh_patches },
#endif
	{ BASIC_PLUGINS_HASH, basic_plugins_patches },
	{ NAS_PLUGIN_HASH, nas_plugin_patches },
	{ EXPLORE_PLUGIN_HASH, explore_plugin_patches },
	{ EXPLORE_CATEGORY_GAME_HASH, explore_category_game_patches },	
	{ BDP_DISC_CHECK_PLUGIN_HASH, bdp_disc_check_plugin_patches },
	{ PS1_EMU_HASH, ps1_emu_patches },
	{ PS1_NETEMU_HASH, ps1_netemu_patches },
	{ GAME_EXT_PLUGIN_HASH, game_ext_plugin_patches },
	{ PSP_EMULATOR_HASH, psp_emulator_patches },
	{ LIBSYSUTIL_SAVEDATA_PSP_HASH, libsysutil_savedata_psp_patches },
#endif
	{ EMULATOR_API_HASH, emulator_api_patches },
	{ PEMUCORELIB_HASH, pemucorelib_patches },
	{ LIBFS_EXTERNAL_HASH, libfs_external_patches }, 
};

#define N_PATCH_TABLE_ENTRIES	(sizeof(patch_table) / sizeof(PatchTableEntry))

#ifdef DEBUG

static char *hash_to_name(uint64_t hash)
{
    switch(hash)
	{
		case OSD_HASH:
			return "sys_init_osd.self";
		break;

		case VSH_HASH:
		case VSH_DECR_HASH:
		case VSH_NRM_HASH:
		case VSH_CEX_HASH:
			return "vsh.self";
		break;

		case EXPLORE_PLUGIN_HASH:
			return "explore_plugin.sprx";
		break;

		case EXPLORE_CATEGORY_GAME_HASH:
			return "explore_category_game.sprx";
		break;

		case BDP_DISC_CHECK_PLUGIN_HASH:
			return "bdp_disccheck_plugin.sprx";
		break;

		case PS1_EMU_HASH:
			return "ps1_emu.self";
		break;

		case PS1_NETEMU_HASH:
			return "ps1_netemu.self";
		break;

		case GAME_EXT_PLUGIN_HASH:
			return "game_ext_plugin.sprx";
		break;

		case PSP_EMULATOR_HASH:
			return "psp_emulator.self";
		break;

		case EMULATOR_API_HASH:
			return "emulator_api.sprx";
		break;

		case EMULATOR_DRM_HASH:
			return "emulator_drm.sprx";
		break;

		case EMULATOR_DRM_DATA_HASH:
			return "emulator_drm.sprx";
		break;

		case PEMUCORELIB_HASH:
			return "PEmuCoreLib.sprx";
		break;

		case LIBFS_EXTERNAL_HASH:
			return "libfs.sprx";
		break;

		case LIBSYSUTIL_SAVEDATA_PSP_HASH:
			return "libsysutil_savedata_psp.sprx";
		break;

		case BASIC_PLUGINS_HASH:
			return "basic_plugins.sprx";
		break;

		case SYSCONF_PLUGIN_HASH:
		case SYSCONF_PLUGIN_CEX_HASH:
			return "sysconf_plugin.sprx";
		break;

/* 		case MMS_HASH:
			return "mms.sprx";
		break; */
/* 		case DA_MINI_HASH:
			return "libda-mini.sprx";
		break; */
/* 		case AGENT_HASH:
			return "sys_agent.self";
		break; */
		default:
			return "UNKNOWN";
		break;		
	}
}

#endif

LV2_HOOKED_FUNCTION_PRECALL_2(int, post_lv1_call_99_wrapper, (uint64_t *spu_obj, uint64_t *spu_args))
{
	// This replaces an original patch of psjailbreak, since we need to do more things
/* #ifdef DEBUG		
	debug_uninstall();
#endif */
	process_t process = get_current_process();

	saved_buf = (void *)spu_args[0x20/8];
	saved_sce_hdr = (void *)spu_args[8/8];

	if (process)
	{
		caller_process = process->pid;
		//DPRINTF("COBRA :::: caller_process = %08X\n", caller_process);
	}
/* #ifdef DEBUG
	debug_hook();
#endif */

	return 0;
}

LV2_PATCHED_FUNCTION(int, modules_patching, (uint64_t *arg1, uint32_t *arg2))
{
	static unsigned int total = 0;
	static uint32_t *buf;
	static uint8_t keys[16];
	static uint64_t nonce = 0;
	static uint32_t val_nop = NOP;
	uint32_t value = 0;
	// uint8_t toggle=0;

	SELF *self;
	uint64_t *ptr;
	uint32_t *ptr32;
	uint8_t *sce_hdr;

	ptr = (uint64_t *)(*(uint64_t *)MKA(TOC+decrypt_rtoc_entry_2));  
	ptr = (uint64_t *)ptr[0x68/8];
	ptr = (uint64_t *)ptr[0x18/8];
	ptr32 = (uint32_t *)ptr;
	sce_hdr = (uint8_t *)saved_sce_hdr; 
	self = (SELF *)sce_hdr;

	uint32_t *p = (uint32_t *)arg1[0x18/8];

	//DPRINTF("COBRA :::: Flags = %x      %x\n", self->flags, (p[0x30/4] >> 16));

	// 3.55 -> 0x29 // +4.30 -> 0x13 (exact firmware since it happens is unknown)
#if defined(FIRMWARE_3_55) || defined(FIRMWARE_3_41)
	if ((p[0x30/4] >> 16) == 0x29)
#else
	if ((p[0x30/4] >> 16) == 0x13)
#endif
	{
		//DPRINTF("COBRA :::: We are in decrypted module or in cobra encrypted\n");

		int last_chunk = 0;
		KeySet *keySet = NULL;

		if (((ptr[0x10/8] << 24) >> 56) == 0xFF)
		{
			ptr[0x10/8] |= 2;
			*arg2 = 0x2C;
			last_chunk = 1;
		}
		else
		{
			ptr[0x10/8] |= 3;
			*arg2 = 6;
		}

		uint8_t *enc_buf = (uint8_t *)ptr[8/8];
		uint32_t chunk_size = ptr32[4/4];
		SPRX_EXT_HEADER *extHdr = (SPRX_EXT_HEADER *)(sce_hdr+self->metadata_offset+0x20);
		uint64_t magic = extHdr->magic&SPRX_EXT_MAGIC_MASK;
		uint8_t keyIndex = extHdr->magic&0xFF;
		// int dongle_decrypt = 0;

		if (magic == SPRX_EXT_MAGIC)
		{
			if (keyIndex >= N_SPRX_KEYS_1)
			{
				DPRINTF("COBRA :::: This key is not implemented yet: %lx:%x\n", magic, keyIndex);
			}
			else
			{
				keySet = &sprx_keys_set1[keyIndex];
			}
		}
		else if (magic == SPRX_EXT_MAGIC2)
		{
			if (keyIndex >= N_SPRX_KEYS_2)
			{
				DPRINTF("COBRA :::: This key is not implemented yet: %lx:%x\n", magic, keyIndex);
			}
			else
			{
				keySet = &sprx_keys_set2[keyIndex];
			}
		}

		if (keySet)
		{
			if (total == 0)
			{
				uint8_t dif_keys[16];

				memset(dif_keys, 0, 16);

/* 				if (dongle_decrypt)
				{
				}
				else
				{ */
					memcpy(keys, extHdr->keys_mod, 16);
				// }

				for (int i = 0; i < 16; i++)
				{
					keys[i] ^= (keySet->keys[15-i] ^ dif_keys[15-i]);
				}

				nonce = keySet->nonce ^ extHdr->nonce_mod;		
			}

			uint32_t num_blocks = chunk_size / 8;

			xtea_ctr(keys, nonce, enc_buf, num_blocks*8);		
			nonce += num_blocks;	

			if (last_chunk)
			{
				get_pseudo_random_number(keys, sizeof(keys));
				nonce = 0;
			}
		}

		memcpy(saved_buf, (void *)ptr[8/8], ptr32[4/4]);

		if (total == 0)
		{
			buf = (uint32_t *)saved_buf;			
		}

		if (last_chunk)
		{
			//DPRINTF("COBRA :::: Total section size: %x\n", total+ptr32[4/4]);			
		}

		saved_buf += ptr32[4/4];		
	}
	else
	{
		decrypt_func(arg1, arg2);
		buf = (uint32_t *)saved_buf;
	}

	total += ptr32[4/4];

	if (((ptr[0x10/8] << 24) >> 56) == 0xFF)
	{
		uint64_t hash = 0;

		for (int i = 0; i < 0x8; i++)  //0x20 bytes only
		{
			hash ^= buf[i+0xb0];  //unique location in all files+static hashes between firmware
		}
/* 		if((total & 0xff0000)==0) //no unique hash for vsh.self
		{
			total=(total&0xfff000); //if size is less than 0x10000 then check for next 4 bits
		}
		else
		{
			total=(total&0xff0000); //copy third byte
		} */
		total=(total&0xfff000); //if size is less than 0x10000 then check for next 4 bits
		hash = ((hash << 32)&0xfffff00000000000)|(total);  //20 bits check, prevent diferent hash just because of minor changes
		total = 0;

/* #if defined(LOGGING)
		DPRINTF("COBRA :::: hash = %lx\n", hash);
#endif */

		switch(hash)
		{
			// pad_data data;
			case OSD_HASH:
				if (cellFsStat(OSD_FILE, &stat) == 0) {
					// DPRINTF("\nCOBRA :::: Flag File detected\n");
					on = 0;
					// flag == 0;
					uint32_t offset = 0x48C69;
					update_mgr_read_eeprom(offset, &flag, LV2_AUTH_ID);
					if (flag == 0x17 || flag == 0x37 || flag == 0x57 || flag == 0x77 || flag == 0x97)
						on = 1; // Systemsoftware Mode
					DPRINTF("COBRA :::: 'OSD-FLAG' detected! EEPROM Flag: 0x%02X | Boot Mode: %s\n", flag, on?(SYS):(REL));
					// sprintf((char*)tmp, "%s", on?(SYS):(REL));
					DPRINTF((char*)tmp);
					if (on) {
						if (hash == OSD_HASH) {
							DPRINTF("COBRA :::: Systemsoftware Mode detected! Disabling Debug Agent: ");
							// buf[sys_agent_offset1/4 && sys_agent_offset2/4] = 0x60000000;
							buf[sys_agent_offset1/4] = val_nop;
							buf[sys_agent_offset2/4] = 0x409E0054;
							sprintf((char*)tmp, "%s\n", buf?(YES):(NO));
							DPRINTF((char*)tmp);
						}
					}
				}
			break;

			case VSH_HASH:
			case VSH_DECR_HASH:
			case VSH_NRM_HASH:
			case VSH_CEX_HASH:
				if (condition_vsh_check) {
					vsh_check = hash;
					if (cellFsStat(FLAG_FILE, &stat) == 0) {
						// DPRINTF("\nCOBRA :::: Flag File detected\n");
						on = 0;
						uint32_t offset = 0x48C69;
						update_mgr_read_eeprom(offset, &flag, LV2_AUTH_ID);
						if (flag == 0x17 || flag == 0x37 || flag == 0x57 || flag == 0x77 || flag == 0x97)
							on = 1; // Systemsoftware Mode
/* 						else if (flag == 0x17) {
							on = 1; // Systemsoftware Mode (test PS3)
						} */
						DPRINTF("\nCOBRA :::: 'NOMOD-FLAG' detected! EEPROM Flag: 0x%02X | Boot Mode: %s", flag, on?(SYS):(REL));
						// sprintf((char*)tmp, "%s", on?(SYS):(REL));
						// DPRINTF((char*)tmp);
						if (!on) {
							if (hash == VSH_HASH || hash == VSH_NRM_HASH/*  || VSH_DECR_HASH */) {
								DPRINTF("\nCOBRA :::: Release Mode detected! Disabling VSH Debug Agent Module: ");
								buf[vsh_debug_agent_offset1/4] = MAKE_JUMP_VALUE(vsh_debug_agent_offset1, vsh_debug_agent_offset2);
								// buf[vsh_debug_agent_offset1/4] = 0x4800002C;
								sprintf((char*)tmp, "%s", buf?(YES):(NO));
								DPRINTF((char*)tmp);
							}
/* 							else if (hash == VSH_DECR_HASH) {
								DPRINTF("\nCOBRA :::: Release Mode detected! Disabling VSH Debug Agent Module: ");
								buf[decr_vsh_debug_agent_offset1/4] = MAKE_JUMP_VALUE(decr_vsh_debug_agent_offset1, decr_vsh_debug_agent_offset2);
								// buf[vsh_debug_agent_offset1/4] = 0x4800002C;
								sprintf((char*)tmp, "%s", buf?(YES):(NO));
								DPRINTF((char*)tmp);
							} */
/* 							else if (hash == VSH_CEX_HASH) {
								DPRINTF("COBRA :::: Release Mode detected! Disabling VSH Debug Agent Module: ");
								// DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);
								buf[cex_vsh_debug_agent_offset1/4] = value1;			
								// DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", cex_vsh_debug_agent_offset1, value1);
								// DPRINTF("COBRA :::: Disable VSH Debug Agent Module: ");
								sprintf((char*)tmp, "%s", buf?(YES):(NO));
								DPRINTF((char*)tmp);
							} */
						}
					}
					if (hash == VSH_HASH || hash == VSH_NRM_HASH/*  || VSH_DECR_HASH */) {
						DPRINTF("\nCOBRA :::: Disabling DEX sacd Module: ");
						// value = MAKE_JUMP_VALUE(vsh_sacd_offset1, vsh_sacd_offset2);
						buf[vsh_sacd_offset1/4] = MAKE_JUMP_VALUE(vsh_sacd_offset1, vsh_sacd_offset2);
						// buf[vsh_sacd_offset1/4] = 0x4800002C;
						sprintf((char*)tmp, "%s\n", buf?(YES):(NO));
						DPRINTF((char*)tmp);
						DPRINTF("COBRA :::: Disabling DEX soundvisualizer Module: ");
						buf[vsh_sfx_offset1/4] = MAKE_JUMP_VALUE(vsh_sfx_offset1, vsh_sfx_offset2);
						// buf[vsh_sfx_offset1/4] = 0x48000080;
						sprintf((char*)tmp, "%s\n", buf?(YES):(NO));
						DPRINTF((char*)tmp);
					}
					else if (hash == VSH_DECR_HASH) {
						DPRINTF("\nCOBRA :::: Disabling DECR sacd Module: ");
						buf[decr_vsh_sacd_offset1/4] = MAKE_JUMP_VALUE(decr_vsh_sacd_offset1, decr_vsh_sacd_offset2);
						// buf[decr_vsh_sacd_offset1/4] = 0x4800002C;
						sprintf((char*)tmp, "%s\n", buf?(YES):(NO));
						DPRINTF((char*)tmp);
						DPRINTF("COBRA :::: Disabling DECR soundvisualizer Module: ");
						buf[decr_vsh_sfx_offset1/4] = MAKE_JUMP_VALUE(decr_vsh_sfx_offset1, decr_vsh_sfx_offset2);
						// buf[decr_vsh_sfx_offset1/4] = 0x48000080;
						sprintf((char*)tmp, "%s\n", buf?(YES):(NO));
						DPRINTF((char*)tmp);
					}
					else if (hash == VSH_CEX_HASH) {
						DPRINTF("\nCOBRA :::: Disabling CEX sacd Module: ");
						buf[cex_vsh_sacd_offset1/4] = MAKE_JUMP_VALUE(cex_vsh_sacd_offset1, cex_vsh_sacd_offset2);
						// buf[cex_vsh_sacd_offset1/4] = 0x4800002C;
						sprintf((char*)tmp, "%s\n", buf?(YES):(NO));
						DPRINTF((char*)tmp);
						DPRINTF("COBRA :::: Disabling CEX soundvisualizer Module: ");
						buf[cex_vsh_sfx_offset1/4] = MAKE_JUMP_VALUE(cex_vsh_sfx_offset1, cex_vsh_sfx_offset2);
						// buf[cex_vsh_sfx_offset1/4] = 0x48000080;
						sprintf((char*)tmp, "%s\n", buf?(YES):(NO));
						DPRINTF((char*)tmp);
					}
				}
			break;

			case EMULATOR_DRM_HASH:
				if (condition_psp_keys)
				{
					DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

					value = LI(R5, psp_code);
					buf[psp_drm_tag_overwrite/4] = value;

					// DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", psp_drm_tag_overwrite, value);
				}
			break;

			case EMULATOR_DRM_DATA_HASH:
				if (condition_psp_keys)
				{
					DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

					buf[psp_drm_key_overwrite/4] = psp_tag;

					// DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", psp_drm_key_overwrite, psp_tag);

					memcpy(buf+((psp_drm_key_overwrite+8)/4), psp_keys, 16);

					// DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", psp_drm_key_overwrite, psp_keys);
				}
			break;

			case BASIC_PLUGINS_HASH:
/* 				if (condition_psp_change_emu)
				{
					memcpy(((char *)buf)+pspemu_path_offset, pspemu_path, sizeof(pspemu_path));
					memcpy(((char *)buf)+psptrans_path_offset, psptrans_path, sizeof(psptrans_path));
				} */
				if (condition_rsod)
				{
					if (cellFsStat(RSOD_FLAG, &stat) == 0) {
						DPRINTF("COBRA :::: 'RSOD-FLAG' detected! Applying RSOD-Bypass\n");
						DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

						value = MAKE_JUMP_VALUE(rsod_check_offset1, rsod_check_offset2);
						buf[rsod_check_offset1/4] = value;			

						DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", rsod_check_offset1, value);
					}
				}
				if (condition_psxemu)
				{
					// condition_net_psxemu = 0;
					condition_psxemu = 0;
					// if(toggle)
						// toggle = 0;
						if (cellFsStat(NET_FLAG, &stat) == 0)
						{
							DPRINTF("COBRA :::: 'PSX-FLAG' detected! Changing 'Classic' ps1_emu to ps1_netemu\n");
							DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

							// value = val_nop;
							buf[ps1emu_type_check_offset/4] = val_nop;			

							DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", ps1emu_type_check_offset, val_nop);
							// toggle=0;
							// condition_toggle_psxemu=0;
						}
						else
						{
							if (cellFsStat(PSX_FLAG, &stat) == 0)
							{
								DPRINTF("COBRA :::: 'PSX-FLAG' detected! Changing 'Classic' ps1_emu to ps1_netemu\n");
								DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

								value = 0x409E000C;
								buf[ps1emu_type_check_offset/4] = value;			

								DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", ps1emu_type_check_offset, value);
							}
						}
					// }
/* 					if (pad_get_data(&data) >= ((PAD_BTN_OFFSET_DIGITAL+1)*2)) {
						if((data.button[PAD_BTN_OFFSET_DIGITAL] & PAD_CTRL_CROSS) == PAD_CTRL_CROSS) {
							DPRINTF("COBRA :::: Button Shortcut detected. Changing 'Soft' ps1_emu to ps1_netemu\n");
							DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

							buf[ps1emu_type_check_offset/4] = val_nop;			

							DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", ps1emu_type_check_offset, val_nop);
						}
					} */
				}
/* 				else if (condition_psx_psxemu)
				{
					// condition_psx_psxemu = 0;
					if(toggle){
						// toggle = 0;
						if (cellFsStat(PSX_FLAG, &stat) == 0) {
							DPRINTF("COBRA :::: 'PSX-FLAG' detected! Changing 'Classic' ps1_emu to ps1_netemu\n");
							DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

							value = 0x409E000C;
							buf[ps1emu_type_check_offset/4] = value;			

							DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", ps1emu_type_check_offset, value);
						}
					}
				} */
			break;

			case PEMUCORELIB_HASH:
				if (condition_pemucorelib){
					if (cellFsStat(PEMU_FLAG, &stat) == 0) {
						DPRINTF("COBRA :::: 'PEMU_FLAG' detected! Applying PSP Extra Save-Patch\n");
						DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

						value = LI(R31, 1);
						buf[psp_extra_savedata_patch/4] = value;

						DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", psp_extra_savedata_patch, value);
					}
/* 					if (pad_get_data(&data) >= ((PAD_BTN_OFFSET_DIGITAL+1)*2)) {
						if((data.button[CELL_BTN_OFFSET_DIGITAL2] & 
						(PAD_CTRL_R1|PAD_CTRL_CROSS)) == (PAD_CTRL_R1|PAD_CTRL_CROSS)) {
							DPRINTF("COBRA :::: Button Shortcut detected! Applying pemucorelib Extra Savedata Patch...\n");
							DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

							uint32_t value = LI(R31, 1);
							buf[psp_extra_savedata_patch/4] = value;

							DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", psp_extra_savedata_patch, value);
						}
					} */
				}
			break;

/* 			case LIBFS_EXTERNAL_HASH:
				if (condition_amg) {
					// buf[psp_extra_savedata_patch/4] = load_game_plugins();
							DPRINTF("COBRA :::: Now loading GAME plugin\n");
							int current_slot = 0;
							if (prx_load_game_plugin(current_slot, PRX_GAME, NULL, 0) >=0)
							{
								DPRINTF("COBRA :::: GAME Plugin %s loaded into Slot: %x\n", PRX_GAME, current_slot);
								// current_slot++;
								// num_loaded++;
							}
				}
			break; */
/* 			case SYSCONF_PLUGIN_HASH:
				if (condition_amg) {
					if (cellFsStat(AMG_FLAG, &stat) == 0) {
						DPRINTF("COBRA :::: 'AMG-FLAG' detected! Disabling x3_amgsdk System Module...\n");
						DPRINTF("COBRA :::: Now patching DEX %s %lx\n", hash_to_name(hash), hash);

						value = MAKE_JUMP_VALUE(amg_offset1, amg_offset2);
						buf[amg_offset1/4] = value;

						DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", amg_offset1, value);
					}
				}
			break; */
/* 			case SYSCONF_PLUGIN_CEX_HASH:
				if (condition_amg) {
					if (cellFsStat(AMG_FLAG, &stat) == 0) {
						DPRINTF("COBRA :::: 'AMG-FLAG' detected! Disabling x3_amgsdk System Module...\n");
						DPRINTF("COBRA :::: Now patching CEX %s %lx\n", hash_to_name(hash), hash);

						value = MAKE_JUMP_VALUE(cex_amg_offset1, cex_amg_offset2);
						buf[cex_amg_offset1/4] = value;

						DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", cex_amg_offset1, value);
					}
				}
			break; */
/* 			case SYSCONF_PLUGIN_DECR_HASH:
				if (condition_amgsdk) {
					if (cellFsStat(AMG_FLAG, &stat) == 0) {
						DPRINTF("COBRA :::: 'AMG_FLAG' detected! Disabling x3_amgsdk System Module...\n");
						DPRINTF("COBRA :::: Now patching DECR %s %lx\n", hash_to_name(hash), hash);

						value = MAKE_JUMP_VALUE(decr_amg_offset1, decr_amg_offset2);
						buf[decr_amg_offset1/4] = value;

						DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", decr_amg_offset1, value);
					}
				}
			break; */
/* 			case MMS_HASH:
				if (condition_amg)
				{
					if (cellFsStat(AMG_FLAG, &stat) == 0)
					{
						DPRINTF("COBRA :::: 'AMG_FLAG' detected! Disabling x3_amgsdk System Module...\n");
						DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

						uint32_t value = NOP;
						buf[amg_offset/4] = value;

						DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", amg_offset, value);
					}
				}
				if (condition_amg)
				{
				if (cellFsStat(AMG_FLAG, &stat) == 0) {
					DPRINTF("COBRA :::: 'AMG_FLAG' detected! Disabling x3_amgsdk System Module...\n");
					DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);

					// uint32_t value = NOP;
					uint32_t value = 0x00000000;
					buf[amg_offset1/4] = value;
					buf[amg_offset2/4] = value;
					buf[amg_offset3/4] = value;
					// buf[amg_offset4/4] = value;
					// buf[amg_offset5/4] = value;
					// buf[amg_offset6/4] = value;
					// buf[amg_offset7/4] = value;
					// buf[amg_offset8/4] = value;

					DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", amg_offset1, value);
					DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", amg_offset2, value);
					DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", amg_offset3, value);
					// DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", amg_offset4, value);
					// DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", amg_offset5, value);
					// DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", amg_offset6, value);
					// DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", amg_offset7, value);
					// DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", amg_offset8, value);
				}
				}
			break; */
/* 			case GAME_EXT_PLUGIN_HASH:
					if (pad_get_data(&data) >= ((PAD_BTN_OFFSET_DIGITAL+1)*2))
					{
						if((data.button[PAD_BTN_OFFSET_DIGITAL] & (PAD_CTRL_R3|PAD_CTRL_R2)) == (PAD_CTRL_R3|PAD_CTRL_R2))
						{
							DPRINTF("COBRA :::: Button Shortcut detected! Calling lv1_panic\n");
							lv1_panic(1);
						}
					}
			break; */
/* 			case DA_MINI_HASH:
				DPRINTF("COBRA :::: Debug Agent detected. Enable 'SYS_TTY_WRITE'\n");
				do_patch(0x8000000000356040ULL, 0x80000000002A4408ULL);
			break;

			case CATEGORY_SETTING_HASH:
				if(do_peek(0x8000000000356040ULL) == 0x80000000002A4408ULL){
					DPRINTF("COBRA :::: XMB detected. Enable 'COBRA_TTY_WRITE'\n");
					do_patch(0x8000000000356040ULL, 0x8000000000521298ULL);
				}
			break; */
			default:
				//Do nothing
			break;
		}

		for (int i = 0; i < N_PATCH_TABLE_ENTRIES; i++)
		{
			if (patch_table[i].hash == hash)
			{
				if (condition_vsh_check)
				{
					switch(hash)
					{
						case VSH_HASH:
							DPRINTF("COBRA :::: Now patching spoofed DEBUG %s %lx\n", hash_to_name(hash), hash);
						break;

						case VSH_DECR_HASH:
							DPRINTF("COBRA :::: Now patching TOOL %s %lx\n", hash_to_name(hash), hash);
						break;

						case VSH_NRM_HASH:
							DPRINTF("COBRA :::: Now patching normal DEBUG %s %lx\n", hash_to_name(hash), hash);
						break;

						case VSH_CEX_HASH:
							DPRINTF("COBRA :::: Now patching spoofed RETAIL %s %lx\n", hash_to_name(hash), hash);
						break;

						default:
							DPRINTF("COBRA :::: Now patching %s %lx\n", hash_to_name(hash), hash);
						break;
					}
				}
/* 				if (condition_amg)
				{
					switch(hash) {
						case LIBFS_EXTERNAL_HASH:
							DPRINTF("COBRA :::: Now loading GAME plugin\n");
							// load_game_plugins();
							// int current_slot = 0, num_loaded = 0;
							int current_slot = 0;
							if (prx_load_game_plugin(current_slot, PRX_GAME, NULL, 0) >=0)
							{
								DPRINTF("COBRA :::: GAME Plugin %s loaded into Slot: %x\n", PRX_GAME, current_slot);
								// current_slot++;
								// num_loaded++;
							}
						break;
					}
				} */

				int j = 0;
				SprxPatch *patch = &patch_table[i].patch_table[j];

				while (patch->offset != 0)
				{
					if (*patch->condition)
					{
						buf[patch->offset/4] = patch->data;							
						DPRINTF("COBRA :::: Offset: 0x%08X | Data: 0x%08X\n", (uint32_t)patch->offset, (uint32_t)patch->data);
						//DPRINTF("COBRA :::: Offset: %lx\n", &buf[patch->offset/4]);
					}

					j++;
					patch = &patch_table[i].patch_table[j];					
				}

				break;
			}
		}
	}

	return 0;
}

/* LV2_HOOKED_FUNCTION_COND_POSTCALL_2(int, pre_modules_verification, (uint32_t *ret, uint32_t error))
{
	// Patch original from psjailbreak. Needs some tweaks to fix some games //	
	//DPRINTF("COBRA :::: err = %x\n", error);
	if (error == 0x13)
	{
		//dump_stack_trace2(10);
		//return DO_POSTCALL; // Fixes Mortal Kombat //
	}
		
	*ret = 0;
	return 0;
} */

void pre_map_process_memory(void *object, uint64_t process_addr, uint64_t size, uint64_t flags, void *unk, void *elf, uint64_t *out);

#ifdef PS3MAPI
uint8_t cleared_stage1 = 0;
#elif CORE
static void unhook_and_clear(void)
{
	// Unhook this function. Also, clear stage1 now.
	suspend_intr();
	unhook_function_with_postcall(map_process_memory_symbol, pre_map_process_memory, 7);
	resume_intr();
	memset((void *)MKA(0x7f0000), 0, 0x10000);
}
#endif

LV2_HOOKED_FUNCTION_POSTCALL_7(void, pre_map_process_memory, (void *object, uint64_t process_addr, uint64_t size, uint64_t flags, void *unk, void *elf, uint64_t *out))
{
	//DPRINTF("COBRA :::: Map %lx %lx %s\n", process_addr, size, get_current_process() ? get_process_name(get_current_process())+8 : "KERNEL");

	// Not the call address, but the call to the caller (process load code for .self)
	if (get_call_address(1) == (void *)MKA(process_map_caller_call))
	{
		if ((process_addr == 0x10000) && (size == vsh_text_size) && (flags == 0x2008004)
#ifdef PS3MAPI
		&& (cleared_stage1 == 0)
#endif
		)
		{
			if (condition_vsh_check)
			{
				switch(vsh_check)
				{
					case VSH_HASH:
						DPRINTF("COBRA :::: Making spoofed DEBUG VSH text writeable, Size: 0x%lx\n", size);
					break;

					case VSH_DECR_HASH:
						DPRINTF("COBRA :::: Making spoofed TOOL VSH text writeable, Size: 0x%lx\n", size);
					break;

					case VSH_NRM_HASH:
						DPRINTF("COBRA :::: Making normal DEBUG VSH text writeable, Size: 0x%lx\n", size);
					break;

					case VSH_CEX_HASH:
						DPRINTF("COBRA :::: Making spoofed RETAIL VSH text writeable, Size: 0x%lx\n", size);
					break;

					default:
						DPRINTF("COBRA :::: WARNING: Unknown VSH loaded.\n Cannot make VSH text writeable\n");
					break;
				}
			}

			// Change flags, RX -> RWX, make vsh text writeable
			set_patched_func_param(4, 0x2004004);
			// We can clear stage1. 
#ifdef CORE
			unhook_and_clear();
#elif PS3MAPI
			if (cleared_stage1 == 0) {cleared_stage1 = 1; memset((void *)MKA(0x7f0000), 0, 0x10000);}
#endif
		}
#ifdef PS3MAPI
		else if  (flags == 0x2008004) set_patched_func_param(4, 0x2004004);// Change flags, RX -> RWX
#endif
	}	
}

#ifdef BC
int toggle_cobra_stage(void)
{
	if ((cellFsStat(CB_LOCATION_CEX, &stat) == 0) && (cellFsStat(CB_LOCATION_DEX, &stat) == 0)){
		cellFsRename(CB_LOCATION_CEX, CB_LOCATION_CEX".bak");
		cellFsRename(CB_LOCATION_DEX, CB_LOCATION_DEX".bak");
	}
	return 0;
}
int toggle_sysaudio(void)
{
	if (cellFsStat(SM_LOCATION, &stat) == 0) off = 1; else on = 1;
	if (off) cellFsRename(SA_LOCATION, SP_LOCATION);
	else if (on) cellFsRename(SA_LOCATION, SM_LOCATION);
	return 0;
}
int toggle_sman(void)
{
	if (cellFsStat(SM_LOCATION, &stat) == 0) on = 1; else off = 1;
	if (on) cellFsRename(SM_LOCATION, SA_LOCATION);
	else if (off) cellFsRename(SP_LOCATION, SA_LOCATION);
	return 0;
}
#endif

LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_8(int, load_process_hooked, (process_t process, int fd, char *path, int r6, uint64_t r7, uint64_t r8, uint64_t r9, uint64_t r10, uint64_t sp_70))
{
	DPRINTF("COBRA :::: PROCESS %s (%08X) loaded\n", path, process->pid);

	// pad_data data;
/* 	while (pad_get_data(&data) >= ((PAD_BTN_OFFSET_DIGITAL+1)*2)) {
		if((data.button[PAD_BTN_OFFSET_DIGITAL] & (PAD_CTRL_L2|PAD_CTRL_R2)) == (PAD_CTRL_L2|PAD_CTRL_R2)) {
			DPRINTF("COBRA :::: Button Shortcut detected! Calling lv1_panic\n");
			lv1_panic(1);
		}
	} */
/* 	if (pad_get_data(&data) >= ((PAD_BTN_OFFSET_DIGITAL+1)*2)) {
		if((data.button[PAD_BTN_OFFSET_DIGITAL] & (PAD_CTRL_L2|PAD_CTRL_R2)) == (PAD_CTRL_L2|PAD_CTRL_R2)) {
			DPRINTF("COBRA :::: Button Shortcut detected! Calling lv1_panic\n");
			lv1_panic(1);
		}
	} */
	if (!vsh_process)
	{
		if ((strcmp(path, "/dev_hdd1/PS3UPDATE/ps3swu.self") == 0) || 
			(strcmp(path, "/dev_hdd1/PS3UPDATE/ps3swu2.self") == 0)) {
			up_mode = 1;
			DPRINTF("COBRA :::: Update Mode detected. Map Paths is disabled\n");
		}
		else if (strcmp(path, "/dev_flash/vsh/module/vsh.self") == 0) {
			vsh_process = process;
/* 			uint32_t offset = 0x48C69;
			uint8_t value;
			on = 0;
			update_mgr_read_eeprom(offset, &value, LV2_AUTH_ID);
			DPRINTF("COBRA :::: Boot Mode Flag: 0x%02X\n", value);
			if (value == 0x37) {
				on = 1; // Systemsoftware Mode
			}
			else
			if (value == 0x17) {
				on = 1; // Systemsoftware Mode
			}
			DPRINTF("COBRA :::: Boot Mode: ");
			sprintf((char*)tmp, "%s\n", on?(SYS):(REL));
			DPRINTF((char*)tmp);
			if (on){
				sys_mode = 1; // Systemsoftware Mode
			} */
		}
		else if (strcmp(path, "emer_init.self") == 0) {
			DPRINTF("COBRA :::: Safe Mode detected. Trying to disable stage2: ");
			safe_mode = 1;
			if (toggle_cobra_stage() == 0) off = 1;
			if (off){
				off = 0;
				if (toggle_sysaudio() == 0) off = 1;
				if (off){
					off = 0;
					if (toggle_sman() == 0) off = 1;
				}
			}
			sprintf((char*)tmp, "%s\n", off?(YES):(NO));
			DPRINTF((char*)tmp);
#ifdef PAY
			cellFsRename(BOOT_PLUGINS_KERNEL_FILE, BOOT_PLUGINS_KERNEL_FILE".bak");
/* 			if (!off || !sysaudio || !sman){
			if (!off || !sysaudio || !sman) DPRINTF("COBRA: Couldn't disable stage2\n", result?((char*)"OK"):((char*)"ERROR")); else DPRINTF("COBRA: OK\n");
				result = 0;
			} */
/* 			int off = 0, sysaudio = 0, sman = 0;
			// DPRINTF("COBRA: Trying to disable stage2...\n");
			if (cellFsStat(CB_LOCATION, &stat) == 0){
				if(cellFsRename(CB_LOCATION, CB_LOCATION".bak") == 0) off = 1;
				if (off){
					if (cellFsRename(SA_LOCATION, SP_LOCATION) == 0) sysaudio = 1;
				}
				if (sysaudio){
					if (cellFsRename(SM_LOCATION, SA_LOCATION) == 0) sman = 1;
				}
				if (!off || !sysaudio || !sman)
					DPRINTF("COBRA: Couldn't disable stage2\n");
				else
					DPRINTF("COBRA: stage2 disabled\n");
			} */
/* 			uint32_t offset;
			uint8_t value;
			for (offset = 0x2F00; offset < 0x03100; offset ++)
			{
				update_mgr_read_eeprom(offset, &value, LV2_AUTH_ID);
				DPRINTF("%02X", value);
			}
			for (offset = 0x48000; offset < 0x48100; offset++)
			{
				update_mgr_read_eeprom(offset, &value, LV2_AUTH_ID);
				DPRINTF("%02X", value);
			}
			for (offset = 0x48800; offset < 0x48900; offset++)
			{
				update_mgr_read_eeprom(offset, &value, LV2_AUTH_ID);
				DPRINTF("%02X", value);
			}
			for (offset = 0x48C00; offset < 0x48E00; offset++)
			{
				update_mgr_read_eeprom(offset, &value, LV2_AUTH_ID);
				DPRINTF("%02X", value);
			} */
#endif
		}
		else if (strcmp(path, "/dev_flash/ps2emu/ps2_netemu.self") == 0) {
			netemu2_process = process;
			DPRINTF("COBRA :::: PS2 Mode detected");
		}
/* 		else if (strcmp(path, "/dev_flash/sys/internal/sys_init_osd.self") == 0) {
			osd_process = process;
			DPRINTF("COBRA :::: 'SYS_INIT' Mode detected\n");
		} */
	}
	if ((strcmp(path, "/app_home/PS3_GAME/USRDIR/EBOOT.BIN") == 0) || (strcmp(path, "/dev_bdvd/PS3_GAME/USRDIR/EBOOT.BIN") == 0) || (strstr(path, "PS3_GAME/USRDIR/")) || (strstr(path, "hdd0/game/")))
	{
	// if (strstr(path, "PS3_GAME/USRDIR/") || strstr(path, "hdd0/game/")) {
		DPRINTF("COBRA :::: GAME Mode detected\n");
		//char *name = get_process_name(process)+8;	
		// char *name = get_process_name(get_current_process())+8;
		game_process = process;
		// game_process = get_current_process();
		// game_process = get_process_name(*process);
		// timer_usleep(SECONDS(13));
		// load_game_plugins();
	}
	else if (strcmp(path, "/dev_flash/ps1emu/ps1_emu.self") == 0)
	{
		DPRINTF("COBRA :::: PS1 'Classic Mode' detected\n");
		// emu1_process = process;
		uint64_t size=0x5343450000000000;
		int dst=0;
		if (cellFsStat(PSX_FLAG, &stat) != 0){
			// cellFsUnlink(PSX_FLAG);
			cellFsOpen(PSX_FLAG, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &dst, 0666, NULL, 0);
			cellFsWrite(dst, &size, 4, &size);
			cellFsClose(dst);
		}
		else 
		{
			if (cellFsStat(NET_FLAG, &stat) != 0)
			{
				cellFsOpen(NET_FLAG, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &dst, 0666, NULL, 0);
				cellFsWrite(dst, &size, 4, &size);
				cellFsClose(dst);
			}
		}
			// cellFsUnlink(PSX_FLAG);
		// condition_net_psxemu = 0;
		// toggle = 0;
		condition_psxemu = 0;
	}
	else if (strcmp(path, "/dev_flash/ps1emu/ps1_netemu.self") == 0)
	{
		DPRINTF("COBRA :::: PS1 'NET Mode' detected\n");
		// netemu1_process = process;
		uint64_t size=0x5343450000000000;
		int dst=0;
		if (cellFsStat(NET_FLAG, &stat) != 0){
			// cellFsUnlink(NET_FLAG);
			cellFsOpen(NET_FLAG, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &dst, 0666, NULL, 0);
			cellFsWrite(dst, &size, 4, &size);
			cellFsClose(dst);
		}
		else 
		{
			if (cellFsStat(PSX_FLAG, &stat) != 0)
			{
				cellFsOpen(PSX_FLAG, CELL_FS_O_WRONLY | CELL_FS_O_CREAT | CELL_FS_O_TRUNC, &dst, 0666, NULL, 0);
				cellFsWrite(dst, &size, 4, &size);
				cellFsClose(dst);
			}
		}
			// cellFsUnlink(NET_FLAG);
		// condition_net_psxemu = 0;
		// toggle = 0;
		condition_psxemu = 0;
	}
/* 	if (vsh_process) {
		if (strstr(path, "PS3_GAME/USRDIR/") || strstr(path, "hdd0/game/")) {
			DPRINTF("COBRA :::: GAME Mode detected\n");
			game_process = process;
			load_game_plugins();
		}
		else if (strcmp(path, "/dev_flash/ps1emu/ps1_emu.self") == 0) {
			emu1_process = process;
			DPRINTF("COBRA :::: PS1 'Classic Mode' detected");
		}
		else if (strcmp(path, "/dev_flash/ps1emu/ps1_netemu.self") == 0) {
			netemu1_process = process;
			DPRINTF("COBRA :::: PS1 'netemu Mode' detected");
		}
		else if (strstr(path, "hdd0/game/")) {
			DPRINTF("COBRA :::: HDD GAME Mode detected\n");
			game_process = process;
		}
	} */

	// if (vsh_process) unhook_function_on_precall_success(load_process_symbol, load_process_hooked, 9); //Hook no more needed

	condition_psxemu = 0;
	return 0;
}

// prx_load_vsh_plugin
int prx_load_vsh_plugin(unsigned int slot, char *path, void *arg, uint32_t arg_size)
{
	void *kbuf, *vbuf;
	sys_prx_id_t prx;
	int ret;	

	if (slot >= MAX_VSH_PLUGINS || (arg != NULL && arg_size > KB(64)))
		return EINVAL;

	if (vsh_plugins[slot] != 0) return EKRESOURCE;

	if (cellFsStat(path, &stat) != 0 || stat.st_size < 0x230) return EINVAL; // prevent a semi-brick (black screen on start up) if the sprx is 0 bytes (due a bad ftp transfer).

	loading_plugin = 1;
	// if(strstr(path, "dev_flash")) { ret = prx_start_modules2(vsh_process, path); goto exit; }
	// else prx = prx_load_module(vsh_process, 0, 0, path);
	prx = prx_load_module(vsh_process, 0, 0, path);
	loading_plugin  = 0;

	if (prx < 0) return prx;

	if (arg && arg_size > 0)
	{	
		page_allocate_auto(vsh_process, KB(64), 0x2F, &kbuf);
		page_export_to_proc(vsh_process, kbuf, 0x40000, &vbuf);
		memcpy(kbuf, arg, arg_size);		
	}
	else vbuf = NULL;

	// if(strstr(path, "dev_flash")) ret = prx_start_module(prx, vsh_process, 0, &vbuf);
	// else ret = prx_start_module_with_thread(prx, vsh_process, 0, (uint64_t)vbuf);
	ret = prx_start_module_with_thread(prx, vsh_process, 0, (uint64_t)vbuf);

	if (vbuf)
	{
		page_unexport_from_proc(vsh_process, vbuf);
		page_free(vsh_process, kbuf, 0x2F);
	}

	on = 0;
	if (ret == 0)
	{
		vsh_plugins[slot] = prx;
		on = 1;
	}
	else
	{
		// if(strstr(path, "dev_flash")) prx_stop_module(prx, vsh_process, 0, 0);
		// else prx_stop_module_with_thread(prx, vsh_process, 0, 0);
		prx_stop_module_with_thread(prx, vsh_process, 0, 0);
		prx_unload_module(prx, vsh_process);
	}
// exit:
	sprintf((char*)txt, "COBRA :::: Load VSH Plugin: %s -> Error: %x\n", on?(YES):(NO), ret);
	DPRINTF((char*)txt);

	return ret;
}
int sys_prx_load_vsh_plugin(unsigned int slot, char *path, void *arg, uint32_t arg_size)
{
	return prx_load_vsh_plugin(slot, get_secure_user_ptr(path), get_secure_user_ptr(arg), arg_size);
}
int prx_unload_vsh_plugin(unsigned int slot)
{
	int ret;
	sys_prx_id_t prx;

	DPRINTF("COBRA :::: Trying to unload VSH Plugin Slot: %x\n", slot);

	if (slot >= MAX_VSH_PLUGINS)
		return EINVAL;

	prx = vsh_plugins[slot];
	DPRINTF("COBRA :::: Current Plugin: %08X\n", prx);

	if (prx == 0)
		return ENOENT;	

	ret = prx_stop_module_with_thread(prx, vsh_process, 0, 0);
	if (ret == 0)
		ret = prx_unload_module(prx, vsh_process);
	else
		DPRINTF("COBRA :::: Stop VSH Plugin Error: %x\n", ret);

	on = 0;
	if (ret == 0)
	{
		vsh_plugins[slot] = 0;
		// DPRINTF("COBRA :::: Unload VSH Plugin Success\n");
		on = 1;
	}
	sprintf((char*)txt, "COBRA :::: Unload VSH Plugin: %s -> Error: %x\n", on?(YES):(NO), ret);
	DPRINTF((char*)txt);
	// else
		// DPRINTF("COBRA :::: Unload VSH Plugin Error : %x!\n", ret);

	return ret;
}
int sys_prx_unload_vsh_plugin(unsigned int slot)
{
	return prx_unload_vsh_plugin(slot);
}

// prx_load_game_plugin
int prx_load_game_plugin(unsigned int slot, char *path, void *arg, uint32_t arg_size)
{
	void *kbuf, *vbuf;
	sys_prx_id_t prx;
	int ret;	

	if (slot >= 5 || (arg != NULL && arg_size > KB(64)))
		return EINVAL;

	if (game_plugins[slot] != 0)
		return EKRESOURCE;

	loading_plugin = 1;
	prx = prx_load_module(game_process, 0, 0, path);
	loading_plugin  = 0;

	if (prx < 0)
		return prx;

	if (arg && arg_size > 0)
	{	
		page_allocate_auto(game_process, KB(64), 0x2F, &kbuf);
		page_export_to_proc(game_process, kbuf, 0x40000, &vbuf);
		memcpy(kbuf, arg, arg_size);		
	}
	else
		vbuf = NULL;

	ret = prx_start_module_with_thread(prx, game_process, 0, (uint64_t)vbuf);

	if (vbuf)
	{
		page_unexport_from_proc(game_process, vbuf);
		page_free(game_process, kbuf, 0x2F);
	}

	on = 0;
	if (ret == 0)
	{
		game_plugins[slot] = prx;
		// DPRINTF("COBRA :::: Load GAME Plugin Success\n");
		on = 1;
	}
	else
	{
		prx_stop_module_with_thread(prx, game_process, 0, 0);
		prx_unload_module(prx, game_process);
		// DPRINTF("COBRA :::: Load GAME Plugin Error: %x!\n", ret);
	}
	sprintf((char*)txt, "COBRA :::: Load GAME Plugin: %s -> Error: %x\n", on?(YES):(NO), ret);
	DPRINTF((char*)txt);

	return ret;
}
int sys_prx_load_game_plugin(unsigned int slot, char *path, void *arg, uint32_t arg_size)
{
	return prx_load_game_plugin(slot, get_secure_user_ptr(path), get_secure_user_ptr(arg), arg_size);
}
/* int prx_unload_game_plugin(unsigned int slot)
{
	int ret;
	sys_prx_id_t prx;

	DPRINTF("COBRA :::: Trying to unload GAME Plugin Slot%x\n", slot);

	if (slot >= 5)
		return EINVAL;

	prx = game_plugins[slot];
	DPRINTF("COBRA :::: Current Plugin: %08X\n", prx);

	if (prx == 0)
		return ENOENT;	

	ret = prx_stop_module_with_thread(prx, game_process, 0, 0);
	if (ret == 0)
		ret = prx_unload_module(prx, game_process);
	else
		DPRINTF("COBRA :::: Stop GAME Plugin Error: %x!\n", ret);

	on = 0;
	if (ret == 0)
	{
		game_plugins[slot] = 0;
		on = 1;
	}
	sprintf((char*)txt, "COBRA :::: Unload GAME Plugin: %s -> Error: %x\n", on?(YES):(NO), ret);
	DPRINTF((char*)txt);

	return ret;
}
int sys_prx_unload_game_plugin(unsigned int slot)
{
	return prx_unload_game_plugin(slot);
} */

static int read_text_line(int fd, char *line, unsigned int size, int *eof)
{
	int i = 0;
	int line_started = 0;

	if (size == 0)
		return -1;

	*eof = 0;

	while (i < (size-1))
	{
		uint8_t ch;
		uint64_t r;

		if (cellFsRead(fd, &ch, 1, &r) != 0 || r != 1)
		{
			*eof = 1;
			break;
		}

		if (!line_started)
		{
			if (ch > ' ')
			{
				line[i++] = (char)ch;
				line_started = 1;
			}
		}
		else
		{
			if (ch == '\n' || ch == '\r')
				break;

			line[i++] = (char)ch;
		}
	}

	line[i] = 0;

	// Remove space chars at end
	for (int j = i-1; j >= 0; j--)
	{
		if (line[j] <= ' ')
		{
			line[j] = 0;
			i = j;
		}
		else
		{
			break;
		}
	}

	return i;
}

#ifdef PAY
uint64_t load_plugin_kernel(char *path)
{
	CellFsStat stat;
	int file;
	int (* func)(void);
	uint64_t read;
	if(cellFsStat(path, &stat)==0)
	{
		if(stat.st_size>4)
		{
			if(cellFsOpen(path, CELL_FS_O_RDONLY, &file, 0, NULL, 0)==0)
			{
				void *skprx=alloc(stat.st_size,0x27);
				if(skprx)
				{
					if(cellFsRead(file, skprx, stat.st_size, &read)==0)
					{	
						f_desc_t f;
						f.addr=skprx;
						f.toc=(void *)MKA(TOC);
						func=(void *)&f;
						func();
						uint64_t resident=(uint64_t)skprx;
						return resident;
					}
					else
					{
						dealloc(skprx, 0x27);
						return -2;
					}
				}
				else
				{
					return 0;
				}
			}
			else
			{
				return -1;
			}
		}
	}
	return -1;
}
int get_vsh_proc()
{
	uint32_t tmp_pid_list[16];
	uint64_t *proc_list = *(uint64_t **)MKA(TOC+process_rtoc_entry_1);	
	proc_list = *(uint64_t **)proc_list;
	proc_list = *(uint64_t **)proc_list;
	for (int i = 0; i < 16; i++)
	{
		process_t process = (process_t)proc_list[1];	
		proc_list += 2;	
		if ((((uint64_t)process) & 0xFFFFFFFF00000000ULL) != MKA(0)) {tmp_pid_list[i] = 0; continue;}
		char *proc_name = get_process_name(process);
		if ( 0 < strlen(proc_name))
		{
			if(strstr(proc_name, "vsh"))
			{
				vsh_process=process;
				break;
			}
		}
	}
	return 0;
}
void load_boot_plugins_kernel(void)
{
	int fd;
	int current_slot_kernel = 0;
	int num_loaded_kernel = 0;
	
	if (safe_mode)
	{
/* 		// cellFsUnlink(BOOT_PLUGINS_KERNEL_FILE);
		// return;
		DPRINTF("COBRA :::: Attempting to rename boot_plugins_kernel.txt.bak\n");

		int src, dst;
		uint64_t rw;

		if (cellFsOpen(BOOT_PLUGINS_KERNEL_FILE, CELL_FS_O_RDONLY, &src, 0, NULL, 0) != 0)
		{
			DPRINTF("COBRA :::: Open Src read failed\n");
			return;
		}

		if (cellFsOpen(BOOT_PLUGINS_KERNEL_FILE".bak", CELL_FS_O_WRONLY|CELL_FS_O_CREAT|CELL_FS_O_TRUNC, &dst, 0666, NULL, 0) != 0)
		{
			DPRINTF("COBRA :::: Open dst write failed\n");
			cellFsClose(src);
			return;
		}

		uint8_t *buf;

		if (page_allocate_auto(NULL, 0x10000, 0x2F, (void **)&buf) != 0)
		{
			DPRINTF("COBRA :::: Page_allocate failed\n");
			cellFsClose(src);
			cellFsClose(dst);
			return;
		}

		memset(buf, 0, 0x10000);

		DPRINTF("COBRA :::: Enter copy loop\n");
		uint64_t total = 0;

		while (1)
		{
			if (cellFsRead(src, buf, 0x10000, &rw) != 0)
			{
				DPRINTF("COBRA :::: cellFsRead failed\n");
				cellFsClose(src);
				cellFsClose(dst);
				page_free(NULL, buf, 0x2F);
				return;
			}

			if (cellFsWrite(dst, buf, rw, &rw) != 0)
			{
				DPRINTF("COBRA :::: cellFsWrite failed\n");
				cellFsClose(src);
				cellFsClose(dst);
				page_free(NULL, buf, 0x2F);
				return;
			}

			total += rw;
			
			if (rw < 0x10000)
				break;
		}

		cellFsClose(src);
		cellFsClose(dst);
		page_free(NULL, buf, 0x2F);

		DPRINTF("COBRA :::: Copy finished (%ld Bytes)\n", total);

		cellFsUnlink(BOOT_PLUGINS_KERNEL_FILE); */
		return;
	}
	
	// if (!vsh_process) return;	  //lets wait till vsh so we dont brick the console perma!
	if (!vsh_process) get_vsh_proc();	  //lets wait till vsh so we dont brick the console perma!

	if (cellFsOpen(BOOT_PLUGINS_KERNEL_FILE, CELL_FS_O_RDONLY, &fd, 0, NULL, 0) == 0)
	{
		while (num_loaded_kernel < MAX_BOOT_PLUGINS_KERNEL)
		{
			char path[128];
			int eof;			
			
			if (read_text_line(fd, path, sizeof(path), &eof) > 0)
			{
				uint64_t ret = load_plugin_kernel(path);
					
				if (ret >= 0)
				{
					DPRINTF("COBRA :::: kernel BOOT Plugin %s loaded into Slot: %x\n", path, current_slot_kernel);
					current_slot_kernel++;
					num_loaded_kernel++;
				}			
			}
			
			if (eof)
				break;
		}

		cellFsClose(fd);
	}
}
#endif

void load_boot_plugins(void)
{
	int fd;
	int current_slot = BOOT_PLUGINS_FIRST_SLOT;
	int num_loaded = 0;

	if (safe_mode)
	{
#ifdef TC
/* 		int off = 0, sysaudio = 0, sman = 0;
			if (cellFsStat(CB_LOCATION, &stat) == 0){
				if(cellFsRename(CB_LOCATION, CB_LOCATION".bak") == 0) off = 1;
				if (off){
					if (cellFsRename(SA_LOCATION, SP_LOCATION) == 0) sysaudio = 1;
				}
				if (sysaudio){
					if (cellFsRename(SM_LOCATION, SA_LOCATION) == 0) sman = 1;
				}
				if (!off || !sysaudio || !sman)
					DPRINTF("COBRA :::: Couldn't disable stage2\n");
				else
					DPRINTF("COBRA :::: stage2 disabled\n");
			} */
/* 		int off = 0, sysaudio = 0, sman = 0;
		DPRINTF("COBRA :::: Safe Mode detected! Trying to disable stage2...\n");
		if (toggle_cobra_stage() == 0) off = 1;
		if (off){
			if (toggle_sysaudio() == 0) sysaudio = 1;
		}
		if (sysaudio){
			if (toggle_sman() == 0) sman = 1;
		}
		if (!off || !sysaudio || !sman)
			DPRINTF("COBRA :::: Couldn't disable stage2\n");
		else
			DPRINTF("COBRA :::: stage2 disabled\n"); */
/* 		int src, dst, stage=0, boot=0;
		uint64_t rw;
		if(cellFsStat(STAGE2_PATH, &stat)==0)
		{
			DPRINTF("COBRA :::: Trying to disable COBRA Payload\n");
			if (cellFsOpen(STAGE2_PATH, CELL_FS_O_RDONLY, &src, 0, NULL, 0) != 0)
			{
				DPRINTF("COBRA :::: Open src read failed\n");
				return;
			}
			if (cellFsOpen(STAGE2_PATH".bak", CELL_FS_O_WRONLY|CELL_FS_O_CREAT|CELL_FS_O_TRUNC, &dst, 0666, NULL, 0) != 0)
			{
				DPRINTF("COBRA :::: Open dst write failed\n");
				cellFsClose(src);
				return;
			}
			stage = 1;
		}
		uint8_t *buf;
		if (page_allocate_auto(NULL, 0x10000, 0x2F, (void **)&buf) != 0)
		{
			DPRINTF("COBRA :::: Page_allocate failed\n");
			cellFsClose(src);
			cellFsClose(dst);
			return;
		}
		memset(buf, 0, 0x10000);
		DPRINTF("COBRA :::: Enter copy loop\n");
		uint64_t total = 0;
		while (1)
		{
			if (cellFsRead(src, buf, 0x10000, &rw) != 0)
			{
				DPRINTF("COBRA :::: cellFsRead failed\n");
				cellFsClose(src);
				cellFsClose(dst);
				page_free(NULL, buf, 0x2F);
				return;
			}
			if (cellFsWrite(dst, buf, rw, &rw) != 0)
			{
				DPRINTF("COBRA :::: cellFsWrite failed\n");
				cellFsClose(src);
				cellFsClose(dst);
				page_free(NULL, buf, 0x2F);
				return;
			}
			total += rw;
			if (rw < 0x10000)
				break;
		}
		cellFsClose(src);
		cellFsClose(dst);
		page_free(NULL, buf, 0x2F);
		DPRINTF("COBRA :::: Copy finished (%ld Bytes)\n", total);
		if(stage)
			cellFsUnlink(STAGE2_PATH); */
/* 		if(boot)
			cellFsUnlink(BOOT_PLUGINS_FILE); */
/* 		else
			cellFsUnlink(BOOT_PLUGINS_FILE".bak"); */
/* 		uint32_t offset=0;
		uint8_t value=0;

		for (offset = 0x2F00; offset < 0x03100; offset ++)
		{
			update_mgr_read_eeprom(offset, &value, LV2_AUTH_ID);
			DPRINTF("COBRA :::: %02X", value);
		}
		for (offset = 0x48000; offset < 0x48100; offset++)
		{
			update_mgr_read_eeprom(offset, &value, LV2_AUTH_ID);
			DPRINTF("COBRA :::: %02X", value);
		}
		for (offset = 0x48800; offset < 0x48900; offset++)
		{
			update_mgr_read_eeprom(offset, &value, LV2_AUTH_ID);
			DPRINTF("COBRA :::: %02X", value);
		}
		for (offset = 0x48C00; offset < 0x48E00; offset++)
		{
			update_mgr_read_eeprom(offset, &value, LV2_AUTH_ID);
			DPRINTF("COBRA :::: %02X", value);
		} */
#endif
		return;
	}

	if (!vsh_process)
		return;

/* 	// KW BEGIN / Special thanks to KW for providing an awesome source
	//Loading webman from flash - must first detect if the toogle is activated
	if (prx_load_vsh_plugin(current_slot, PRX_PATH, NULL, 0) >=0)
	{
		// DPRINTF("Loading integrated artsMAN Plugin into Slot %x\n", current_slot);
		DPRINTF("COBRA :::: Integrated BOOT Plugin %s loaded into Slot: %x\n", PRX_PATH, current_slot);
		current_slot++;
		num_loaded++;
		// webman_loaded=1;
	}
	// KW END */

	if (cellFsOpen(BOOT_PLUGINS_FILE, CELL_FS_O_RDONLY, &fd, 0, NULL, 0) != 0)
		return;

	while (num_loaded < MAX_BOOT_PLUGINS)
	{
		char path[128];
		int eof;

		if (read_text_line(fd, path, sizeof(path), &eof) > 0)
		{
			int ret = prx_load_vsh_plugin(current_slot, path, NULL, 0);

			if (ret >= 0)
			{
				DPRINTF("COBRA :::: BOOT Plugin %s loaded into Slot: %x\n", path, current_slot);
				current_slot++;
				num_loaded++;
			}
		}

		if (eof)
			break;
	}

	cellFsClose(fd);

}
void load_game_plugins(void)
{
	int fd;
	int current_slot = 0;
	int num_loaded = 0;

	if (!game_process)
		return;

	if (prx_load_game_plugin(current_slot, PRX_GAME, NULL, 0) >=0)
	{
		DPRINTF("COBRA :::: GAME Plugin %s loaded into Slot: %x\n", PRX_GAME, current_slot);
		current_slot++;
		num_loaded++;
	}

	if (cellFsOpen(GAME_PLUGINS_FILE, CELL_FS_O_RDONLY, &fd, 0, NULL, 0) != 0)
		return;

	while (num_loaded < 3)
	{
		char path[128];
		int eof;

		if (read_text_line(fd, path, sizeof(path), &eof) > 0)
		{
			int ret = prx_load_game_plugin(current_slot, path, NULL, 0);

			if (ret >= 0)
			{
				DPRINTF("COBRA :::: GAME Plugin %s loaded into Slot: %x\n", path, current_slot);
				current_slot++;
				num_loaded++;
			}
		}

		if (eof)
			break;
	}

	cellFsClose(fd);
	return;
}

#ifdef DEBUG
LV2_HOOKED_FUNCTION_PRECALL_SUCCESS_8(int, create_process_common_hooked, (process_t parent, uint32_t *pid, int fd, char *path, int r7, uint64_t r8, 
									  uint64_t r9, void *argp, uint64_t args, void *argp_user, uint64_t sp_80, 
									 void **sp_88, uint64_t *sp_90, process_t *process, uint64_t *sp_A0,
									  uint64_t *sp_A8))
{
	char *parent_name = get_process_name(parent);
	// DPRINTF("COBRA :::: PROCESS %s (%s) (%08X) created from parent process: %s\n", path, get_process_name(*process), *pid, ((int64_t)parent_name < 0) ? parent_name : "");
	DPRINTF("COBRA :::: PROCESS %s (%s) created from parent process: %s\n", path, get_process_name(*process), ((int64_t)parent_name < 0) ? parent_name : "");
	if (strcmp(path, "/app_home/PS3_GAME/USRDIR/EBOOT.BIN") == 0 || 
		strcmp(path, "/dev_bdvd/PS3_GAME/USRDIR/EBOOT.BIN") == 0 || 
		strstr(path, "PS3_GAME/USRDIR/") || 
		strstr(path, "hdd0/game/")) {
		game_process = *process;
		// game_process = get_current_process_critical();
		// game_process = get_current_process();
		// load_game_plugins();
/* 		int current_slot = 1;
		if (prx_load_game_plugin(current_slot, PRX_GAME, NULL, 0) >=0)
		{
			DPRINTF("COBRA :::: GAME Plugin %s loaded into Slot: %x\n", PRX_GAME, current_slot);
			// current_slot++;
			// num_loaded++;
		} */
	}
	return 0;
}

/* LV2_HOOKED_FUNCTION_POSTCALL_8(void, create_process_common_hooked_pre, (process_t parent, uint32_t *pid, int fd, char *path, int r7, uint64_t r8, 
									  uint64_t r9, void *argp, uint64_t args, void *argp_user, uint64_t sp_80, 
									 void **sp_88, uint64_t *sp_90, process_t *process, uint64_t *sp_A0,
									  uint64_t *sp_A8))
{
	DPRINTF("COBRA :::: Pre-process\n");
	if (strcmp(path, "/app_home/PS3_GAME/USRDIR/EBOOT.BIN") == 0 || 
		strcmp(path, "/dev_bdvd/PS3_GAME/USRDIR/EBOOT.BIN") == 0 || 
		strstr(path, "PS3_GAME/USRDIR/") || 
		strstr(path, "hdd0/game/")) {
		// game_process = *process;
		// game_process = get_current_process_critical();
		// load_game_plugins();
		int current_slot = 1;
		if (prx_load_game_plugin(current_slot, PRX_GAME, NULL, 0) >=0)
		{
			DPRINTF("COBRA :::: GAME Plugin %s loaded into Slot: %x\n", PRX_GAME, current_slot);
			// current_slot++;
			// num_loaded++;
		}
	}
	// return DO_POSTCALL; // Fixes Mortal Kombat //
} */
#endif

void modules_patch_init(void)
{
	hook_function_with_precall(lv1_call_99_wrapper_symbol, post_lv1_call_99_wrapper, 2);
	patch_call(patch_func2 + patch_func2_offset, modules_patching);	
	//hook_function_with_cond_postcall(modules_verification_symbol, pre_modules_verification, 2);
	hook_function_with_postcall(map_process_memory_symbol, pre_map_process_memory, 7);	
	hook_function_on_precall_success(load_process_symbol, load_process_hooked, 9);	
#ifdef DEBUG
	hook_function_on_precall_success(create_process_common_symbol, create_process_common_hooked, 16);
	// hook_function_with_postcall(create_process_common_symbol, create_process_common_hooked_pre, 8);
#endif
}

#ifdef PS3MAPI
#ifdef UNHOOK
void unhook_all_modules(void)
{
	suspend_intr();
	unhook_function_with_precall(lv1_call_99_wrapper_symbol, post_lv1_call_99_wrapper, 2);
	//unhook_function_with_cond_postcall(modules_verification_symbol, pre_modules_verification, 2);
	unhook_function_with_postcall(map_process_memory_symbol, pre_map_process_memory, 7);	
	// unhook_function_on_precall_success(load_process_symbol, load_process_hooked, 9);	
#ifdef DEBUG
	unhook_function_on_precall_success(load_process_symbol, load_process_hooked, 9);	
	unhook_function_on_precall_success(create_process_common_symbol, create_process_common_hooked, 16);
	//unhook_function_with_postcall(create_process_common_symbol, create_process_common_hooked_pre, 8);
#endif
	resume_intr();
}

int ps3mapi_unload_vsh_plugin(char *name)
{
	if (vsh_process <= 0) return ESRCH;
	for (unsigned int slot = 0; slot < MAX_VSH_PLUGINS; slot++)
	{
		if (vsh_plugins[slot] == 0) continue;
		char *filename = alloc(256, 0x35);
		if (!filename) return ENOMEM;
		sys_prx_segment_info_t *segments = alloc(sizeof(sys_prx_segment_info_t), 0x35);
		if (!segments) {dealloc(filename, 0x35); return ENOMEM;}
		sys_prx_module_info_t modinfo;
		memset(&modinfo, 0, sizeof(sys_prx_module_info_t));
		modinfo.filename_size = 256;
		modinfo.segments_num = 1;
		int ret = prx_get_module_info(vsh_process, vsh_plugins[slot], &modinfo, filename, segments);
		if (ret == SUCCEEDED)
		{
			if (strcmp(modinfo.name, get_secure_user_ptr(name)) == 0) 
				{
						dealloc(filename, 0x35);
						dealloc(segments, 0x35);
						return prx_unload_vsh_plugin(slot);
				}				
		}
		dealloc(filename, 0x35);
		dealloc(segments, 0x35);
	}
	return ESRCH;
}
#endif

int ps3mapi_get_vsh_plugin_info(unsigned int slot, char *name, char *filename)
{
	if (vsh_process <= 0) 
		return ESRCH;

	if (vsh_plugins[slot] == 0) 
		return ENOENT;

	char *tmp_filename = alloc(256, 0x35);
	if (!tmp_filename) 
		return ENOMEM;

	sys_prx_segment_info_t *segments = alloc(sizeof(sys_prx_segment_info_t), 0x35);
	if (!segments) {dealloc(tmp_filename, 0x35); 
		return ENOMEM;}

	char tmp_filename2[256];
	char tmp_name[30];
	sys_prx_module_info_t modinfo;
	memset(&modinfo, 0, sizeof(sys_prx_module_info_t));
	modinfo.filename_size = 256;
	modinfo.segments_num = 1;
	int ret = prx_get_module_info(vsh_process, vsh_plugins[slot], &modinfo, tmp_filename, segments);
	
	if (ret == SUCCEEDED)
	{
			sprintf(tmp_name, "%s", modinfo.name);
			ret = copy_to_user(&tmp_name, get_secure_user_ptr(name), strlen(tmp_name));	
			sprintf(tmp_filename2, "%s", tmp_filename);
			ret = copy_to_user(&tmp_filename2, get_secure_user_ptr(filename), strlen(tmp_filename2));
	}
	
	dealloc(tmp_filename, 0x35);
	dealloc(segments, 0x35);
	return ret;
}
#endif

