all: bitmap context_save context_restore

bitmap:
	$(CC) -Wall -fno-stack-protector -fpie -Os -c bitmap.c
	$(CC) -nostdlib -o bitmap.out bitmap.o -Wl,--entry=_entry
	objcopy --dump-section .text=bitmap.bin bitmap.out
	xxd -i bitmap.bin > bitmap_bin.c
	readelf -s bitmap.o | grep __BITMAP_ |  awk '{print "const size_t " $$8 " = 0x" $$2 ";"}' >> bitmap_bin.c
	echo "const unsigned int bitmap_id_hole = 0xDEAD;" >> bitmap_bin.c
	echo "const unsigned int bitmap_shr_id_hole = 0xBEEF;" >> bitmap_bin.c

context_save:
	$(CC) -Wall -fno-stack-protector -fpie -Os -c context_save.c
	$(CC) -nostdlib -o context_save.out context_save.o -Wl,--entry=_entry
	objcopy --dump-section .text=context_save.bin context_save.out
	xxd -i context_save.bin > context_save_bin.c

context_restore:
	$(CC) -Wall -fno-stack-protector -fpie -Os -c context_restore.c
	$(CC) -nostdlib -o context_restore.out context_restore.o -Wl,--entry=_entry
	objcopy --dump-section .text=context_restore.bin context_restore.out
	xxd -i context_restore.bin > context_restore_bin.c

clean:
	rm -rf *.o *_bin.c *.bin *.out


SOURCES += bitmap.c context_save.c context_restore.c
HDEADERS += trampolines.h

format:
	clang-format -sort-includes -style=file -i $(SOURCES)
	clang-format -sort-includes -style=file -i $(HDEADERS)
