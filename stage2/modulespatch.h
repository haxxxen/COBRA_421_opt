#ifndef __MODULESPATCH_H__
#define __MODULESPATCH_H__

#include <lv2/process.h>
#include <lv2/thread.h>
#include <lv2/modules.h>

#define DEFS
#ifdef DEFS
#if defined(FIRMWARE_4_21)
// BIG WARNING: self offsets need to add 0x10000 for address shown in IDA, but not sprxs!
#define OSD_HASH						0xe2a8f00000015000 /* D-REX sys_init_osd.self */
#define VSH_DECR_HASH					0xb6b6d000002e3000 /* D-REX vsh.self */
#define VSH_HASH						0xb6b6d000002df000 /* D-REX vsh.self */
#define VSH_NRM_HASH					0xb6b6d000002e2000 /* D-REX vsh.self.nrm */
#define VSH_CEX_HASH					0xb6b6d000002dc000 /* D-REX vsh.self.cexsp */
/* #define VSH_HASH						0xb6b6d000002de000 // D-REX vsh.self //
#define VSH_NRM_HASH					0xb6b6d000002df000 // D-REX vsh.self.nrm //
#define VSH_CEX_HASH					0xb6b6d000002db000 // D-REX vsh.self.cexsp // */
#define BASIC_PLUGINS_HASH				0x27b600000001f000
#define NAS_PLUGIN_HASH					0xc50d000000025000
#define EXPLORE_PLUGIN_HASH				0xc50d0000000e5000
#define EXPLORE_CATEGORY_GAME_HASH		0xde52a00000057000 /* Rog hash is same as ofw even if file is different. */
#define BDP_DISC_CHECK_PLUGIN_HASH		0x9940000000003000
#define PS1_EMU_HASH					0xcc28b000000a1000
#define PS1_NETEMU_HASH					0xcc28d000000c4000
#define GAME_EXT_PLUGIN_HASH			0xcc2680000001d000
#define PSP_EMULATOR_HASH				0xcc29b00000023000
#define EMULATOR_API_HASH				0x8409f0000001c000
#define PEMUCORELIB_HASH				0x40425000000c2000
#define EMULATOR_DRM_HASH				0xbbb8800000005000
#define EMULATOR_DRM_DATA_HASH			0x2f3ab0000001b000
#define LIBSYSUTIL_SAVEDATA_PSP_HASH	0x0dfdc00000003000
#define LIBFS_EXTERNAL_HASH				0x05fd000000006000
#define SYSCONF_PLUGIN_HASH				0x3c01f00000081000
#define SYSCONF_PLUGIN_CEX_HASH			0x3c01f0000007f000
// #define DA_MINI_HASH					0x06b9300000012000
// #define AGENT_HASH						0xcc28700000035000
// #define MMS_HASH						0x40a1700000045000

// sys_init_osd //FBB4
#define sys_agent_offset1		0xFBFC
#define sys_agent_offset2		0xFBB4
// #define sys_agent_offset3		0xFB5C
// #define sys_agent_offset4		0xFB74

#define VSH_SIZE 0x2FF850
#define VSH_SIZE_NRM 0x2FF850
#define VSH_SIZE_CEX 0x303F08

#define vsh_text_size			0x6B0000 // memsz of first program header aligned to 0x10000 //
// #define decr_vsh_text_size			0x6C0000 // memsz of first program header aligned to 0x10000 //
// #define BASIC_SIZE 0x2F074

// vsh DECR //
#define decr_elf1_func1 			0x5EFDF0
#define decr_elf1_func1_offset 		0x00
#define decr_elf1_func2 			0x2493B4
#define decr_elf1_func2_offset 		0x14
/* // #define game_update_offset		0x2717C4
// #define ps2tonet_patch			0xC9A30 //
// #define ps2tonet_size_patch		0xC9A24 */
#define decr_psp_drm_patch1			0x2466B0 // LI R3, 0
#define decr_psp_drm_patch2			0x247148 // 
#define decr_psp_drm_patch3			0x246D88 // 
#define decr_psp_drm_patch4			0x247590 // 
#define decr_psp_drm_patchA			0x2467CC // 
#define decr_psp_drm_patchB			0x247064 // 
#define decr_psp_drm_patchC			0x246204 // 
#define decr_psp_drm_patchD			0x2467B4 // 
#define decr_psp_drm_patchE			0x2467B8 // 
#define decr_psp_drm_patchF			0x24717C // 
/* // #define revision_offset			0x65BBA0
// #define revision_offset2		0x6FFC1C // In data section //
// #define spoof_version_patch		0xBDBD0
// #define psn_spoof_version_patch		0x1A75AC */
// #define vmode_patch_offset1		0x00448B88
#define decr_vmode_patch_offset		0x448C98
#define decr_vsh_debug_agent_offset1		0xABDD8
#define decr_vsh_debug_agent_offset2		0xABE04
// #define vsh_debug_agent_offset1		0xC5A8C
// #define vsh_debug_agent_offset2		0xC84A0
#define decr_vsh_sacd_offset1		0xC99A8
#define decr_vsh_sacd_offset2		0xC99D4
#define decr_vsh_sfx_offset1		0xC6C08
#define decr_vsh_sfx_offset2		0xC6C88

// vsh DEX //
#define elf1_func1 			0x5ED7C8
#define elf1_func1_offset 		0x00
#define elf1_func2 			0x246D6C
#define elf1_func2_offset 		0x14
/* // #define game_update_offset		0x2717C4
// #define ps2tonet_patch			0xC9A30 //
// #define ps2tonet_size_patch		0xC9A24 */
#define psp_drm_patch1			0x244068 // LI R3, 0
#define psp_drm_patch2			0x244B00 // 
#define psp_drm_patch3			0x244740 // 
#define psp_drm_patch4			0x244F48 // 
#define psp_drm_patchA			0x244184 // 
#define psp_drm_patchB			0x244A1C // 
#define psp_drm_patchC			0x243BBC // 
#define psp_drm_patchD			0x24416C // 
#define psp_drm_patchE			0x244170 // 
#define psp_drm_patchF			0x244B34 // 
/* // #define revision_offset			0x65BBA0
// #define revision_offset2		0x6FFC1C // In data section //
// #define spoof_version_patch		0xBDBD0
// #define psn_spoof_version_patch		0x1A75AC */
// #define vmode_patch_offset1		0x446540
#define vmode_patch_offset		0x446650
#define vsh_debug_agent_offset1		0xABDAC
#define vsh_debug_agent_offset2		0xABDD8
/* // #define vsh_debug_agent_offset1		0xABE60
// #define vsh_debug_agent_offset2		0xC84A0 */
#define vsh_sacd_offset1		0xCA448
#define vsh_sacd_offset2		0xCA474
#define vsh_sfx_offset1		0xC74B8
#define vsh_sfx_offset2		0xC7538

// vsh CEX //
#define cex_elf1_func1 			0x5E5BF0
#define cex_elf1_func1_offset 		0x00
#define cex_elf1_func2 			0x23F560
#define cex_elf1_func2_offset 		0x14
/* // #define game_update_offset		0x269FB8
// #define ps2tonet_patch			0xC44EC
// #define ps2tonet_size_patch		0xC44E0 */
#define cex_psp_drm_patch1			0x23C85C
#define cex_psp_drm_patch2			0x23D2F4
#define cex_psp_drm_patch3			0x23CF34
#define cex_psp_drm_patch4			0x23D73C
#define cex_psp_drm_patchA			0x23C978
#define cex_psp_drm_patchB			0x23D210
#define cex_psp_drm_patchC			0x23C3B0
#define cex_psp_drm_patchD			0x23C960
#define cex_psp_drm_patchE			0x23C964
#define cex_psp_drm_patchF			0x23D328
/* // #define revision_offset			0x653890
// #define revision_offset2		0x6FF280 // In data section //
// #define spoof_version_patch		0xB8D78
// #define psn_spoof_version_patch		0x19FCA4 */
#define cex_vmode_patch_offset		0x43EA78
#define cex_vsh_debug_agent_offset1		0x446650
#define cex_vsh_debug_agent_offset2		0x44667C
#define cex_vsh_sacd_offset1		0xC4F04
#define cex_vsh_sacd_offset2		0xC4F30
#define cex_vsh_sfx_offset1		0xC1F90
#define cex_vsh_sfx_offset2		0xC2010

// basic_plugins //
#define ps1emu_type_check_offset	0x20114
#define pspemu_path_offset		0x4AF28
#define psptrans_path_offset		0x4BB98
#define rsod_check_offset1		0x105E0
#define rsod_check_offset2		0x10600

// explore_plugin //
#define app_home_offset			0x246AE8
// #define ps2_nonbw_offset		0xDAFBC

// sys_config_dex //
#define amg_offset1		0x5005C
#define amg_offset2		0x50088

// sys_config_cex //
#define cex_amg_offset1		0x4E358
#define cex_amg_offset2		0x4E384

/* // mms //0x9A8D0
#define amg_offset1		0x9A8D0
#define amg_offset2		0x9A8D4
#define amg_offset3		0x9A8D8
#define amg_offset4		0x9A8DC
#define amg_offset5		0x9A8E0
#define amg_offset6		0x9A8E4
#define amg_offset7		0x9A8E8
// #define amg_offset8		0x994BC */
/* // mms //0x9924C
#define amg_offset1		0x9924C
#define amg_offset2		0x99250
#define amg_offset3		0x99254
#define amg_offset4		0x9925C
#define amg_offset5		0x99260
#define amg_offset6		0x99264
#define amg_offset7		0x99268
#define amg_offset8		0x9926C */

/* // nas_plugin //
// #define elf2_func1 			0x2DCF0
// #define elf2_func1_offset		0x374
// #define geohot_pkg_offset		0x3174

// explore_category_game //
// #define ps2_nonbw_offset2		0x75460
// #define unk_patch_offset1		0x546C // unknown patch from E3 cfw //
// #define unk_patch_offset2		0x5490 // unknown patch from E3 cfw //

// bdp_disc_check_plugin //
// #define dvd_video_region_check_offset	0x1528

// ps1_emu //
// #define ps1_emu_get_region_offset	0x3E74	

// ps1_netemu //
// #define ps1_netemu_get_region_offset	0xB18BC

// game_ext_plugin //
// #define sfo_check_offset		0x23054
// #define ps2_nonbw_offset3		0x16788
// #define ps_region_error_offset		0x6810
// Disable the check for the current video setting //
#define ps_video_error_offset          0x3171C // li %r3, 0  
#define ps_video_error_offset+4          0x31720 // blr  

// psp_emulator //
#define psp_set_psp_mode_offset 	0x1C18 // the same as 4.70 */

/* emulator_api */ // the same as 4.66 - 4.81
#define psp_read			0x102D8 //
#define psp_read_header			0x1125C //
#define psp_drm_patch5			0x11080 //
#define psp_drm_patch6			0x110B0 //
#define psp_drm_patch7			0x110C8 //
#define psp_drm_patch8			0x110CC //
#define psp_drm_patch9			0x1120C //
#define psp_drm_patch11			0x11210 //
#define psp_drm_patch12			0x11220 //
#define psp_product_id_patch1		0x11320 //
#define psp_product_id_patch3		0x115F8 //
// #define umd_mutex_offset		(0x64B80+0x38C) //
#define umd_mutex_offset		(0x64480+0x38C) //

/* pemucorelib */ // 4.66-4.81 CEX
#define psp_eboot_dec_patch		0x5E6BC // same
#define psp_prx_patch			0x577D8 //
#define psp_savedata_bind_patch1	0x7A4BC //
#define psp_savedata_bind_patch2	0x7A514  //
#define psp_savedata_bind_patch3	0x7A030 //
#define psp_extra_savedata_patch	0x87540 // *4.55 = 0x8753C // 
#define psp_prometheus_patch		0x12EA28 //
#define prx_patch_call_lr		0x5892C //

/* emulator_drm */ // same as 4.66 - 4.81 CEX
#define psp_drm_tag_overwrite		0x4C68 //
#define psp_drm_key_overwrite		(0x27600-0xBE80) //

/* // libsysutil_savedata_psp //
#define psp_savedata_patch1		0x46CC
#define psp_savedata_patch2		0x46A4
// #define psp_savedata_patch3		0x4504
// #define psp_savedata_patch4		0x453C
// #define psp_savedata_patch5		0x4550
// #define psp_savedata_patch6		0x46B8 */

/* libfs (external) */
#define aio_copy_root_offset		0xD5B4

#endif /* FIRMWARE */

#define YES "OK"
#define NO "DISABLED"
#define SYS "Systemsoftware Mode"
#define REL "Release Mode"
#define FLAG_FILE	"/dev_flash/nomod"
#define OSD_FILE	"/dev_flash/noosd"
#define RSOD_FLAG	"/dev_flash/rsod"
#define PSX_FLAG	"/dev_hdd0/tmp/psx"
#define NET_FLAG	"/dev_hdd0/tmp/net"
#define PEMU_FLAG	"/dev_hdd0/tmp/pemu"
#define AMG_FLAG	"/dev_flash/amg"
#define CB_LOCATION_CEX "/dev_rebug/rebug/cobra/stage2.cex"
#define CB_LOCATION_DEX "/dev_rebug/rebug/cobra/stage2.dex"
#define SA_LOCATION "/dev_rebug/sys/internal/sys_audio.sprx"
#define SP_LOCATION "/dev_rebug/sys/internal/sys_plugin.sprx"
#define SM_LOCATION "/dev_rebug/sys/internal/sys_sm.sprx"
#endif /* DEFS */

typedef struct
{
	uint32_t offset;
	uint32_t data;
	uint8_t *condition;
} SprxPatch;

typedef struct
{
	uint64_t hash;
	SprxPatch *patch_table;	

} PatchTableEntry;

typedef struct
{
	uint8_t keys[16];
	uint64_t nonce;	
} KeySet;

// typedef uint32_t sys_prx_id_t;

extern uint8_t condition_ps2softemu;
extern uint8_t condition_apphome;
extern uint8_t condition_psp_iso;
extern uint8_t condition_psp_dec;
extern uint8_t condition_psp_keys;
// extern uint8_t condition_psp_change_emu;
extern uint8_t condition_psp_prometheus;

// extern uint8_t block_peek;

extern uint8_t condition_vsh_check;
extern uint8_t condition_net_psxemu;
extern uint8_t condition_psx_psxemu;
extern uint8_t condition_psxemu;
extern uint8_t toggle;
extern uint64_t vsh_check;

extern process_t vsh_process;
extern uint8_t safe_mode, up_mode, tmp[6], txt[55];
extern int on, off, sys_mode;

extern int toggle_cobra_stage(void);
extern int toggle_sysaudio(void);
extern int toggle_sman(void);

/* Functions for kernel */
void modules_patch_init(void);
//void do_spoof_patches(void);  Spoof is not needed due to REX's static spoof 
void load_boot_plugins(void);
void load_game_plugins(void);
int prx_load_vsh_plugin(unsigned int slot, char *path, void *arg, uint32_t arg_size);
int prx_unload_vsh_plugin(unsigned int slot);

// int prx_load_sys_plugin(unsigned int slot, char *path, void *arg, uint32_t arg_size);
// int prx_unload_sys_plugin(unsigned int slot);
// int prx_load_sys_plugin(char *path, void *arg, uint32_t arg_size);
// int prx_unload_sys_plugin(uint8_t prx);
// int prx_unload_sys_plugin(sys_prx_id_t prx_id);

int prx_load_game_plugin(unsigned int slot, char *path, void *arg, uint32_t arg_size);
int prx_unload_game_plugin(unsigned int slot);

#ifdef PAY
void load_boot_plugins_kernel(void);
#endif

/* Syscalls */
//int sys_vsh_spoof_version(char *version_str);  //Spoof is not needed due to REX's static spoof 
int sys_prx_load_vsh_plugin(unsigned int slot, char *path, void *arg, uint32_t arg_size);
int sys_prx_unload_vsh_plugin(unsigned int slot);
int sys_prx_load_game_plugin(unsigned int slot, char *path, void *arg, uint32_t arg_size);
int sys_prx_unload_game_plugin(unsigned int slot);
int sys_thread_create_ex(sys_ppu_thread_t *thread, void *entry, uint64_t arg, int prio, uint64_t stacksize, uint64_t flags, const char *threadname);
// void update_hashes(void);

#ifdef PS3MAPI
// PS3Mapi v1.2.1
// int ps3mapi_unload_vsh_plugin(char* name); 
#ifdef UNHOOK
void unhook_all_modules(void);
#endif
int ps3mapi_get_vsh_plugin_info(unsigned int slot, char *name, char *filename);
#endif

#endif /* __MODULESPATCH_H__ */
