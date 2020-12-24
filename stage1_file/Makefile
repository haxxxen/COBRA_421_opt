
clean:
	rm -f *DEBUG *.o *.elf *.self *.421 *.bin *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o ../stage0_file/*.bin stage0_file/*.bin ../stage0_file/*.o stage0_file/*.o ../stage0_file/*.elf stage0_file/*.elf ../stage1_file/*.bin stage1_file/*.bin ../stage1_file/*.o stage1_file/*.o ../stage1_file/*.elf stage1_file/*.elf ../stage1_file/*.self stage1_file/*.self lv1/src/*.o debug/src/*.o lv2/src/*.o

all:
	# rm -f *.o *.elf *.self *.421 *.bin *.421c *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	# make -f Makefile_421C --no-print-directory

	# rm -f *.o *.elf *.421 *.bin *.421d *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	# make -f Makefile_421D --no-print-directory

	rm -f *.o *.elf *.421 *.bin *.421c *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	make -f Makefile_421C_dbg --no-print-directory

	rm -f *.o *.elf *.421 *.bin *.421d *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	make -f Makefile_421D_dbg --no-print-directory

	rm -f *.o *.elf  *.421 *.bin *.421c *.421d *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o  ../stage0_file/*.bin

dbg:
	rm -f *.o *.elf *.self *.421 *.bin *.421c *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	make -f Makefile_421C_dbg --no-print-directory

	rm -f *.o *.elf *.421 *.bin *.421d *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	make -f Makefile_421D_dbg --no-print-directory

	rm -f *.o *.elf  *.421 *.bin *.421c *.421d *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o

re:
	rm -f *.o *.elf *.self *.421 *.bin *.421c *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	make -f Makefile_421C --no-print-directory

	rm -f *.o *.elf *.421 *.bin *.421d *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	make -f Makefile_421D --no-print-directory

	rm -f *.o *.elf  *.421 *.bin *.421c *.421d *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
