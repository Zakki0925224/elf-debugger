SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

edb: $(OBJS)
	$(CC) -no-pie -g -o edb $(OBJS)

clean:
	rm -f edb *.o *~ tmp*

.PHONY: clean