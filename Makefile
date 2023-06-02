SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
#LDLIBS=-lcurl

edb: $(OBJS)
	$(CC) -no-pie -g -o edb $(OBJS) #$(LDLIBS)

clean:
	rm -f edb *.o *~ tmp*

.PHONY: clean
