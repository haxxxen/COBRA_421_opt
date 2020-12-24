#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/hid.h>
#include <lv2/pad.h>

int pad_get_data(pad_data *data)
{
	int ret;
	memset(data, 0, sizeof(pad_data));
	// data=0xFF;
	while ((ret = hid_mgr_read_usb(0, data, 0x40, 0)) == 0);	
	// system_call_4(0x1F6, (uint64_t)port, 0xFF, (uint64_t)(uint32_t)data+4, 0x80);
	// while ((ret = hid_mgr_read_usb(0, 0xFF, (uint64_t)(uint32_t)data+4, 0x80)) == 0);	
	if (ret == 0xFFFFFFE8)
	{// USB failed, try BT now...
		uint16_t len;
		do
		{
			len = 0x40;
			ret = hid_mgr_read_bt(0, data, &len, 1);
			if (ret == 0)
				ret = len;
			
		} while (ret == 0);
	}
	return ret;
}

