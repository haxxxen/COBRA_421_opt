#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/memory.h>
#include <lv2/patch.h>
#include <lv2/syscall.h>
#include <lv2/thread.h>
#include <lv2/modules.h>
#include <lv2/io.h>
#include <lv2/error.h>
#include <lv2/symbols.h>
#include <lv1/patch.h>

// #include <lv2/time.h>
#include "cobra_core.h"
#include "modulespatch.h"

//-----------------------------------------------
//PROCESSES
//-----------------------------------------------

int get_all_processes_pid(process_id_t *pid_list)
{
	uint32_t tmp_pid_list[MAX_PROCESS];
	uint64_t *proc_list = *(uint64_t **)MKA(TOC+process_rtoc_entry_1);	
	proc_list = *(uint64_t **)proc_list;
	proc_list = *(uint64_t **)proc_list;
	for (int i = 0; i < MAX_PROCESS; i++)
	{
		process_t process = (process_t)proc_list[1];	
		proc_list += 2;	
		if ((((uint64_t)process) & 0xFFFFFFFF00000000ULL) != MKA(0)) {tmp_pid_list[i] = 0; continue;}
		char *proc_name = get_process_name(process);
		if ( 0 < strlen(proc_name)) tmp_pid_list[i] = process->pid;	
		else tmp_pid_list[i] = 0;
	}
	return copy_to_user(&tmp_pid_list, get_secure_user_ptr(pid_list), sizeof(tmp_pid_list));
}

process_t internal_get_process_by_pid(process_id_t pid)
{
	uint64_t *proc_list = *(uint64_t **)MKA(TOC+process_rtoc_entry_1);	
	proc_list = *(uint64_t **)proc_list;
	proc_list = *(uint64_t **)proc_list;	
	for (int i = 0; i < MAX_PROCESS; i++)
	{
		process_t p = (process_t)proc_list[1];	
		proc_list += 2;		
		if ((((uint64_t)p) & 0xFFFFFFFF00000000ULL) != MKA(0)) continue;
		if (p->pid == pid) return p;
	}
	return NULL;
}

int get_process_name_by_pid(process_id_t pid, char *name)
{
	process_t process = internal_get_process_by_pid(pid);
	if (process <= 0) return ESRCH;
	char proc_name[25];
	sprintf(proc_name, "%s", get_process_name(process));
	return copy_to_user(&proc_name, get_secure_user_ptr(name),  strlen(proc_name));
}

/* int get_process_by_pid(process_id_t pid, process_t process)
{
	uint64_t *proc_list = *(uint64_t **)MKA(TOC+process_rtoc_entry_1);	
	proc_list = *(uint64_t **)proc_list;
	proc_list = *(uint64_t **)proc_list;	
	for (int i = 0; i < MAX_PROCESS; i++)
	{
		process_t p = (process_t)proc_list[1];	
		proc_list += 2;		
		if ((((uint64_t)p) & 0xFFFFFFFF00000000ULL) != MKA(0)) continue;
		if (p->pid == pid) return copy_to_user(&p, get_secure_user_ptr(process), sizeof(process_t));
	}
	return ESRCH;
} */

/* int get_current_process(process_t process)
{
	process_t p = get_current_process();
	if (p <= 0) return ESRCH;
	else return copy_to_user(&p, get_secure_user_ptr(process), sizeof(process_t));
} */

/* int get_current_process_critical(process_t process)
{
	suspend_intr();
	process_t p = get_current_process();
	resume_intr();
	if (p <= 0) return ESRCH;
	else return copy_to_user(&p, get_secure_user_ptr(process), sizeof(process_t));
} */

//-----------------------------------------------
//MEMORY
//-----------------------------------------------

int cobra_set_process_mem(process_id_t pid, uint64_t addr, char *buf, int size)
{
	process_t process = internal_get_process_by_pid(pid);
	if (process <= 0) return ESRCH;
	else return copy_to_process(process, (void *)get_secure_user_ptr(buf), (void *)addr, size);
}

int cobra_get_process_mem(process_id_t pid, uint64_t addr, char *buf, int size)
{
	void *buff;
	process_t process = internal_get_process_by_pid(pid);
	if (process <= 0) return ESRCH;
	buff = alloc(size, 0x27);
	if (!buff) return ENOMEM;
	int ret = copy_from_process(process, (void *)addr, buff, size);
	if (ret != SUCCEEDED) {dealloc(buff, 0x27); return ret;}
	ret = copy_to_user(buff, (void *)get_secure_user_ptr(buf), size);
	dealloc(buff, 0x27);
	return ret;
}

//-----------------------------------------------
//MODULES
//-----------------------------------------------

/* int get_all_process_modules_prx_id(process_id_t pid, sys_prx_id_t *prx_id_list)
{
	process_t process = internal_get_process_by_pid(pid);
	if (process <= 0) return ESRCH;
	sys_prx_id_t tmp_prx_id_list[MAX_MODULES];
	sys_prx_id_t *list;
	uint32_t *unk;
	uint32_t n, unk2;
	list = alloc(MAX_MODULES*sizeof(sys_prx_module_info_t), 0x35);
	if (!list) return ENOMEM;
	unk = alloc(MAX_MODULES*sizeof(uint32_t), 0x35);
	if (!unk) {dealloc(list, 0x35); return ENOMEM;}
	int ret = prx_get_module_list(process, list, unk, MAX_MODULES, &n, &unk2);
	if (ret == SUCCEEDED)
	{
		for (int i = 0; i < MAX_MODULES; i++)
		{
			if (i < n) tmp_prx_id_list[i] = list[i];
			else tmp_prx_id_list[i] = 0;
		}
		ret =copy_to_user(&tmp_prx_id_list, get_secure_user_ptr(prx_id_list), sizeof(tmp_prx_id_list));
	}
	dealloc(list, 0x35);
	dealloc(unk, 0x35);
	return ret;
} */

/* int get_process_module_name_by_prx_id(process_id_t pid, sys_prx_id_t prx_id, char *name)
{
	process_t process = internal_get_process_by_pid(pid);
	if (process <= 0) return ESRCH;
	char *filename = alloc(256, 0x35);
	if (!filename) return ENOMEM;
	char tmp_name[30];
	sys_prx_module_info_t modinfo;
	memset(&modinfo, 0, sizeof(sys_prx_module_info_t));
	modinfo.filename_size = 256;
	int ret = prx_get_module_info2(process, prx_id, &modinfo, filename);
	if (ret == SUCCEEDED)
	{
		sprintf(tmp_name, "%s", modinfo.name);
		ret = copy_to_user(&tmp_name, get_secure_user_ptr(name), strlen(tmp_name));		
	}
	dealloc(filename, 0x35);
	return ret;	
} */

/* int get_process_module_filename_by_prx_id(process_id_t pid, sys_prx_id_t prx_id, char *name)
{
	process_t process = internal_get_process_by_pid(pid);
	if (process <= 0) return ESRCH;
	char *filename = alloc(256, 0x35);
	if (!filename) return ENOMEM;
	char tmp_name[256];
	sys_prx_module_info_t modinfo;
	memset(&modinfo, 0, sizeof(sys_prx_module_info_t));
	modinfo.filename_size = 256;
	int ret = prx_get_module_info2(process, prx_id, &modinfo, filename);
	if (ret == SUCCEEDED)
	{
		sprintf(tmp_name, "%s", filename);
		ret = copy_to_user(&tmp_name, get_secure_user_ptr(name), strlen(tmp_name));		
	}
	dealloc(filename, 0x35);
	return ret;	
} */

int load_process_modules(process_id_t pid, char *path, void *arg, uint32_t arg_size)
{
	process_t process = internal_get_process_by_pid(pid);
	if (process <= 0) return ESRCH;
	path = get_secure_user_ptr(path);
	arg = get_secure_user_ptr(arg);
	void *kbuf, *vbuf;
	sys_prx_id_t prx;
	int ret;	
	if (arg != NULL && arg_size > KB(64))return EINVAL;		
	prx = prx_load_module(process, 0, 0, path);
	if (prx < 0) return prx;
	if (arg && arg_size > 0)
	{	
		page_allocate_auto(process, KB(64), 0x2F, &kbuf);
		page_export_to_proc(process, kbuf, 0x40000, &vbuf);
		memcpy(kbuf, arg, arg_size);		
	}
	else vbuf = NULL;
	ret = prx_start_module_with_thread(prx, process, 0, (uint64_t)vbuf);
	if (vbuf)
	{
		page_unexport_from_proc(process, vbuf);
		page_free(process, kbuf, 0x2F);
	}	
	if (ret != SUCCEEDED)
	{
		prx_stop_module_with_thread(prx, process, 0, 0);
		prx_unload_module(prx, process);
	}
	return ret;
}

/* int unload_process_modules(process_id_t pid, sys_prx_id_t prx_id)
{
	process_t process = internal_get_process_by_pid(pid);
	if (process <= 0) return ESRCH;
	int ret = prx_stop_module_with_thread(prx_id, process, 0, 0);
	if (ret == SUCCEEDED) ret = prx_unload_module(prx_id, process);
	return ret;
} */

int get_vsh_plugin_info(unsigned int slot, char *name, char *filename)
{
	if (vsh_process <= 0) return ESRCH;
	if (vsh_plugins[slot] == 0) return ENOENT;
	char *tmp_filename = alloc(256, 0x35);
	if (!tmp_filename) return ENOMEM;
/* 	sys_prx_segment_info_t *segments = alloc(sizeof(sys_prx_segment_info_t), 0x35);
	if (!segments) {dealloc(tmp_filename, 0x35); return ENOMEM;} */
	char tmp_filename2[256];
	char tmp_name[30];
	sys_prx_module_info_t modinfo;
	memset(&modinfo, 0, sizeof(sys_prx_module_info_t));
	modinfo.filename_size = 256;
/* 	modinfo.segments_num = 1;
	int ret = prx_get_module_info(vsh_process, vsh_plugins[slot], &modinfo, tmp_filename, segments); */
	int ret = prx_get_module_info2(vsh_process, vsh_plugins[slot], &modinfo, tmp_filename);
	if (ret == SUCCEEDED)
	{
			// PRINTF("COBRA :::: %s\n", tmp_filename);
			sprintf(tmp_name, "%s", modinfo.name);
			ret = copy_to_user(&tmp_name, get_secure_user_ptr(name), strlen(tmp_name));	
			sprintf(tmp_filename2, "%s", tmp_filename);
			ret = copy_to_user(&tmp_filename2, get_secure_user_ptr(filename), strlen(tmp_filename2));
			// PRINTF("COBRA :::: %s\n", tmp_filename2);
	}
	dealloc(tmp_filename, 0x35);
	// dealloc(segments, 0x35);
	// return ret;
	return 0;
}

int unload_vsh_plugin_name(char *name)
{
	if (vsh_process <= 0) return ESRCH;
	for (unsigned int slot = 0; slot < MAX_VSH_PLUGINS; slot++)
	{
		if (vsh_plugins[slot] == 0) continue;
		char *filename = alloc(256, 0x35);
		if (!filename) return ENOMEM;
/* 		sys_prx_segment_info_t *segments = alloc(sizeof(sys_prx_segment_info_t), 0x35);
		if (!segments) {dealloc(filename, 0x35); return ENOMEM;} */
		sys_prx_module_info_t modinfo;
		memset(&modinfo, 0, sizeof(sys_prx_module_info_t));
		modinfo.filename_size = 256;
/* 		modinfo.segments_num = 1;
		int ret = prx_get_module_info(vsh_process, vsh_plugins[slot], &modinfo, filename, segments); */
		int ret = prx_get_module_info2(vsh_process, vsh_plugins[slot], &modinfo, filename);
		if (ret == SUCCEEDED)
		{
			if (strcmp(modinfo.name, get_secure_user_ptr(name)) == 0) 
				{
					dealloc(filename, 0x35);
					// dealloc(segments, 0x35);
					return prx_unload_vsh_plugin(slot);
				}				
		}
		dealloc(filename, 0x35);
		// dealloc(segments, 0x35);
	}
	return ESRCH;
}

//-----------------------------------------------
//ADDITIONS
//-----------------------------------------------

/* int dump_threads_info(uint64_t arg)
{
	// DPRINTF("COBRA :::: ----Dump threads info begin----\n");
	PRINTF("COBRA :::: ----Dump threads info begin----\n");
	// int ret = dump_threads_info();
	uint8_t *thread_info = (uint8_t *)MKA(thread_info_symbol);
	int num_threads;
	// char *tmp_filename=0;
	num_threads = *(uint32_t *)&thread_info[8];
	for (int i = 0; i < num_threads; i++)
	{
		// DPRINTF("COBRA :::: Thread: %s   entry: %016lx    PC: %016lx\n", (char *)(thread_info+0x58), *(uint64_t *)(thread_info+0xB0), *(uint64_t *)(thread_info+0x208));
		PRINTF("COBRA :::: %s\n", (char *)(thread_info+0x58));
		thread_info += 0x600;
		// sPRINTF("COBRA :::: %s\n", thread_info);
		// sprintf(tmp_filename, "%s\n", thread_info);
	}
	// DPRINTF("COBRA :::: ----Dump threads info end----\n");
	PRINTF("COBRA :::: ----Dump threads info end----\n");
	// sprintf(tmp_filename, "%s\n", num_threads);
	return 0;
}

int dump_processes_modules_info(process_t process)
{
	uint64_t *proc_list = *(uint64_t **)MKA(TOC+process_rtoc_entry_1);
	proc_list = *(uint64_t **)proc_list;
	proc_list = *(uint64_t **)proc_list;	
	for (int i = 0; i < 0x10; i++)
	{
		process_t process = (process_t)proc_list[1];
		proc_list += 2;		
		if ((((uint64_t)process) & 0xFFFFFFFF00000000ULL) != MKA(0))
			continue;
		// dump_process_modules_info(process);	
		sys_prx_id_t *list;
		uint32_t *unk;
		uint32_t n, unk2;
		// DPRINTF("COBRA :::: ******** %s ********\n", get_process_name(process));
		PRINTF("COBRA :::: ******** %s ********\n", get_process_name(process));
		list = alloc(SPRX_NUM*sizeof(sys_prx_module_info_t), 0x35);
		unk = alloc(SPRX_NUM*sizeof(uint32_t), 0x35);
		// if (prx_get_module_list(process, list, unk, SPRX_NUM, &n, &unk2) == 0)
		prx_get_module_list(process, list, unk, SPRX_NUM, &n, &unk2);
		char *filename = alloc(256, 0x35);
		// sys_prx_segment_info_t *segments = alloc(sizeof(sys_prx_segment_info_t), 0x35);
		for (int i = 0; i < n; i++)
		{
			sys_prx_module_info_t modinfo;
			memset(&modinfo, 0, sizeof(sys_prx_module_info_t));
			modinfo.filename_size = 256;
			if (prx_get_module_info2(process, list[i], &modinfo, filename) == 0)
			{
				// DPRINTF("COBRA :::: Module %s\nText_addr:%08lX\n", filename, segments[0].base);				
				PRINTF("COBRA :::: %s\n", filename);				
				// sprintf(tmp_name, "%s\n", filename);
				// ret = copy_to_user(&tmp_name, get_secure_user_ptr(name), strlen(tmp_name));	
				// sprintf(tmp_filename2, "%s", tmp_filename);
				// ret = copy_to_user(&tmp_filename2, get_secure_user_ptr(filename), strlen(tmp_filename2));
			}
		}
		dealloc(filename, 0x35);
		// PRINTF("COBRA :::: ****************\n");
		PRINTF("COBRA :::: ****************\n");
		dealloc(list, 0x35);
		dealloc(unk, 0x35);
		return 0;
		// return ret;
	}	
	return 0;
} */

/* static void dump_threads_info(void)
{
	uint8_t *thread_info = (uint8_t *)MKA(thread_info_symbol);
	int num_threads;
	num_threads = *(uint32_t *)&thread_info[8];
	for (int i = 0; i < num_threads; i++)
	{
		// PRINTF("COBRA :::: Thread: %s   entry: %016lx    PC: %016lx\n", (char *)(thread_info+0x58), *(uint64_t *)(thread_info+0xB0), *(uint64_t *)(thread_info+0x208));
		PRINTF("COBRA :::: %s\n", (char *)(thread_info+0x58));
		thread_info += 0x600;
	}
}

static void dump_threads_info_test(uint64_t arg0)
{	
	PRINTF("COBRA :::: Threads info will be dumped in 13 seconds.\n");
	timer_usleep(SECONDS(13));
	PRINTF("COBRA :::: ----Dump threads info begin----\n");
	dump_threads_info();
	PRINTF("COBRA :::: ----Dump threads info end----\n");
	ppu_thread_exit(0);
}

void do_dump_threads_info_test(void)
{
	thread_t my_thread;
	ppu_thread_create(&my_thread, dump_threads_info_test, 0, -0x1D8, 0x4000, 0, "Dump Threads");		
}

static void dump_process_modules_info(process_t process)
{
	sys_prx_id_t *list;
	uint32_t *unk;
	uint32_t n, unk2;
	PRINTF("COBRA :::: ******** %s ********\n", get_process_name(process));
	list = alloc(SPRX_NUM*sizeof(sys_prx_module_info_t), 0x35);
	unk = alloc(SPRX_NUM*sizeof(uint32_t), 0x35);
	if (prx_get_module_list(process, list, unk, SPRX_NUM, &n, &unk2) == 0)
	{
		char *filename = alloc(256, 0x35);
		sys_prx_segment_info_t *segments = alloc(sizeof(sys_prx_segment_info_t), 0x35);
		for (int i = 0; i < n; i++)
		{
			sys_prx_module_info_t modinfo;
			memset(&modinfo, 0, sizeof(sys_prx_module_info_t));
			modinfo.filename_size = 256;
			modinfo.segments_num = 1;
			if (prx_get_module_info(process, list[i], &modinfo, filename, segments) == 0)
			{
				PRINTF("COBRA :::: Module %s\nText_addr:%08lX\n", filename, segments[0].base);				
			}
		}
		dealloc(filename, 0x35);
		dealloc(segments, 0x35);
	}
	PRINTF("COBRA :::: ****************\n");
	dealloc(list, 0x35);
	dealloc(unk, 0x35);
}

static void dump_processes_modules_info(void)
{
	uint64_t *proc_list = *(uint64_t **)MKA(TOC+process_rtoc_entry_1);
	proc_list = *(uint64_t **)proc_list;
	proc_list = *(uint64_t **)proc_list;	
	for (int i = 0; i < 0x10; i++)
	{
		process_t process = (process_t)proc_list[1];
		proc_list += 2;		
		if ((((uint64_t)process) & 0xFFFFFFFF00000000ULL) != MKA(0))
			continue;
		dump_process_modules_info(process);	
	}	
}

static void dump_modules_info_test(uint64_t arg0)
{	
	PRINTF("COBRA :::: Modules info will be dumped in 71 seconds.\n");
	timer_usleep(SECONDS(71));
	dump_processes_modules_info();	
	ppu_thread_exit(0);
}

void do_dump_modules_info_test(void)
{
	thread_t my_thread;
	ppu_thread_create(&my_thread, dump_modules_info_test, 0, -0x1D8, 0x4000, 0, "Dump Modules Info");		
} */

