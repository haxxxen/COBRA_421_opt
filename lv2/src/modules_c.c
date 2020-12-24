#include <lv2/lv2.h>
#include <lv2/modules.h>
#include <lv2/security.h>
#include <lv2/thread.h>
// #include "../../stage2/common.h"
#include "../../stage2/modulespatch.h"
// #include <lv2/libc.h>

int prx_get_module_name_by_address(process_t process, void *addr, char *name)
{
	sys_prx_module_info_t modinfo;
	sys_prx_id_t id = prx_get_module_id_by_address(process, addr);
	
	if (id < 0)
		return id;
	
	memset(&modinfo, 0, sizeof(modinfo));
	int ret = prx_get_module_info(process, id, &modinfo, NULL, NULL);
	
	if (ret < 0)
		return ret;
	
	strncpy(name, modinfo.name, 30);
	return 0;
}

int prx_start_module_with_thread(sys_prx_id_t id, process_t process, uint64_t flags, uint64_t arg)
{
	int ret;
	uint64_t meminfo[5];
	uint32_t toc[2];
	thread_t thread;
	uint64_t exit_code;
	
	meminfo[0] = sizeof(meminfo);
	meminfo[1] = 1;
	
	ret = prx_start_module(id, process, flags, meminfo);
	if (ret != 0)
		return ret;	
	
	ret = copy_from_process(process, (void *)meminfo[2], toc, sizeof(toc));
	if (ret != 0)
		return ret;
	
	ret = ppu_user_thread_create(process, &thread, toc, arg, 0, 0x1000, PPU_THREAD_CREATE_JOINABLE, "");
	if (ret != 0)
		return ret;
	
	ppu_thread_join(thread, &exit_code);
	meminfo[1] = 2;
	meminfo[3] = 0;
	
	return prx_start_module(id, process, flags, meminfo);
}

int prx_stop_module_with_thread(sys_prx_id_t id, process_t process, uint64_t flags, uint64_t arg)
{
	int ret;
	uint64_t meminfo[5];
	uint32_t toc[2];
	thread_t thread;
	uint64_t exit_code;
	
	meminfo[0] = sizeof(meminfo);
	meminfo[1] = 1;
	
	ret = prx_stop_module(id, process, flags, meminfo);
	if (ret != 0)
		return ret;	
	
	ret = copy_from_process(process, (void *)meminfo[2], toc, sizeof(toc));
	if (ret != 0)
		return ret;
	
	ret = ppu_user_thread_create(process, &thread, toc, arg, 0, 0x1000, PPU_THREAD_CREATE_JOINABLE, "");
	if (ret != 0)
		return ret;
	
	return ppu_thread_join(thread, &exit_code);	
}

int prx_start_modules(sys_prx_id_t id, process_t process, uint64_t flags, uint64_t arg)
{
	int ret;
	uint64_t meminfo[5];
	uint32_t toc[2];
	
	meminfo[0] = sizeof(meminfo);
	meminfo[1] = 1;
	
	// sys_prx_id_t prx = prx_load_module(process, 0, 0, path);
	
	ret = prx_start_module(id, process, flags, meminfo);
	if (ret != 0)
		return ret;	
	
	ret = copy_from_process(process, (void *)meminfo[2], toc, sizeof(toc));
	if (ret != 0)
		return ret;
	
	meminfo[1] = 2;
	meminfo[3] = 0;
	
	// return prx_start_module(id, process, flags, meminfo);
	return id;
}
// int prx_start_modules2(process_t process)
int prx_start_modules2(process_t process, char *path)
{
	void *kbuf, *vbuf, *arg = 0;
	int ret, loading_plugin;
	// uint64_t flags;
	uint32_t arg_size = 0;
	// const char *path;

	// uint64_t meminfo[5];
	// uint32_t toc[2];

	loading_plugin = 1;
	sys_prx_id_t id = prx_load_module(process, 0, 0, path);
	loading_plugin  = 0;

	if (id < 0) return id;

	if (arg && arg_size > 0)
	{	
		page_allocate_auto(process, KB(64), 0x2F, &kbuf);
		page_export_to_proc(process, kbuf, 0x40000, &vbuf);
		memcpy(kbuf, arg, arg_size);		
	}
	else vbuf = NULL;

	ret = prx_start_module(id, process, 0, vbuf);
	if (ret != 0) return ret;	

	if (vbuf) {
		page_unexport_from_proc(process, vbuf);
		page_free(process, kbuf, 0x2F);
	}

	int on = 0;
	if (ret == 0) {
		on = 1;
	}
	else {
		prx_stop_module(id, process, 0, 0);
		prx_unload_module(id, process);
	}

	// ret = copy_from_process(process, (void *)meminfo[2], toc, sizeof(toc));
	// if (ret != 0) return ret;

	// meminfo[1] = 2;
	// meminfo[3] = 0;
	// sprintf((char*)txt, "COBRA :::: Load VSH Plugin: %s -> Error: %x\n", on?(YES):(NO), ret);
	// DPRINTF((char*)txt);

	// return prx_start_module(id, process, flags, meminfo);
	return on;
}


