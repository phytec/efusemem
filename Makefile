CC = gcc
CFLAGS = -Wall -pedantic

target = efusemem

src = efusemem.c
obj = $(src:c=o)

$(target): $(obj)
	$(CC) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $<

.PHONY: clean

clean:
	rm -f $(target) *.o
