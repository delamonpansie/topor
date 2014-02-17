
CFLAGS += -Iev -O0 -g3 -Wall

obj += topor_ev.o
obj += topor_main.o
obj += topor_opt.o

topor_ev.o: CFLAGS = -Iev -O2

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

topor: $(obj)
	$(CC) $(LDFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -f $(obj) topor tags
