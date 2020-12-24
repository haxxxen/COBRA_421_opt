#ifndef __LV2_SECURITY_H__
#define __LV2_SECURITY_H__

#include <lv2/lv2.h>

#define LV1_AUTH_ID	 0x1FF0000002000001
#define LV2_AUTH_ID	 0x1050000003000001
#define UM_AUTH_ID	 0x107000000F000001
#define VTRM_AUTH_ID	 0x107000000E000001
#define LV2DIAG_AUTH_ID	 0x1070000300000001
#define EMER_AUTH_ID	 0x10700003FC000001
#define DM_AUTH_ID	 0x1070000027000001
#define SM_AUTH_ID	 0x107000001D000001
#define INIT_AUTH_ID	 0x1070000017000001
// #define SM_AUTH_ID	 0x107000001D000001
// #define SM_AUTH_ID	 0x107000001D000001

typedef struct _MD5Context
{
	uint8_t data[0x58];
} MD5Context;

LV2_EXPORT int get_pseudo_random_number(void *buf, uint64_t size);

LV2_EXPORT void md5_reset(MD5Context *ctx);
LV2_EXPORT void md5_update(MD5Context *ctx, void *buf, uint32_t size);
LV2_EXPORT void md5_final(void *hash, MD5Context *ctx);

static INLINE void md5_once(void *buf, uint32_t size, void *hash)
{
	MD5Context ctx;
	
	md5_reset(&ctx);
	md5_update(&ctx, buf, size);
	md5_final(hash, &ctx);
}

// Use 0 for paid
LV2_EXPORT int ss_get_open_psid(void *psid, uint64_t paid);

// Use LV2_AUTH_ID for auth_id
LV2_EXPORT int update_mgr_read_eeprom(uint32_t offset, uint8_t *byte, uint64_t auth_id);
LV2_EXPORT int update_mgr_write_eeprom(uint32_t offset, uint8_t byte, uint64_t auth_id);

/*
 Syscon brick experiment. Proceed with caution :)

static void syscon_brick_experiment(void)
{
	uint32_t offset;
	
	for (offset = 0x48c00; offset < 0x48c62; offset ++)
	{
		// Do not change the 0x02 value
		// The idea is that the spu number (0x48c30) is overwritten with this value. 
		// Who knows if the system will really apply that number, and its consequences :)		
		update_mgr_write_eeprom(offset, 0x02, LV2_AUTH_ID);
	}
	
	for (offset = 0x2f00; offset < 0x3100; offset++)
	{
		// Just a random value
		update_mgr_write_eeprom(offset, 0xA5, LV2_AUTH_ID);
	}
}*/

LV2_EXPORT int sys_sm_ring_buzzer(uint64_t unknown1, uint8_t unknown2, uint32_t unknown3);

#endif /* __LV2_SECURITY_H__ */


