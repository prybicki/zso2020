TESTS=write_read pwrite_pread writev_readv pwritev_preadv pwritev2_preadv2
EXEC=$(addprefix nosync_,$(TESTS)) \
     $(addprefix sync_,$(TESTS)) \
     $(addprefix default_,$(TESTS)) \
     $(addprefix partial_,$(TESTS)) \
     ftrunc lseek fstat multi_fd multi_fd_sync

all:  $(EXEC)

clean:
	rm -f $(EXEC) *.o

nosync_%: do_%.o main_nosync.o
	$(CC) -o $@ $< main_nosync.o

partial_%: do_%.o main_partial.o
	$(CC) -o $@ $< main_partial.o

sync_%: do_%.o main_sync.o
	$(CC) -o $@ $< main_sync.o

default_%: do_%.o main_default.o
	$(CC) -o $@ $< main_default.o
