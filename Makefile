SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

edb: $(OBJS)
	$(CC) -g -o edb $(OBJS)

clean:
	rm -f edb *.o *~ tmp*

.PHONY: clean