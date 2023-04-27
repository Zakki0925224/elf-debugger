SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

build: $(OBJS)
	$(CC) -no-pie -o test $(OBJS)

clean:
	rm -f *.o *~ tmp*

.PHONY: clean