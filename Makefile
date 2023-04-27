SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

elf-dbgr: $(OBJS)
	$(CC) -o edb $(OBJS)

clean:
	rm -f edb *.o *~ tmp*

.PHONY: clean