SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

elf-dbgr: $(OBJS)
	$(CC) -o elf-dbgr $(OBJS)

clean:
	rm -f elf-dbgr *.o *~ tmp*

.PHONY: clean