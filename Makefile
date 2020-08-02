CC = gcc
DEBUG = -O0 -ggdb -g
RElease = -O3
INCLUDE = -I/usr/local/include
CFLAGS = $(DEBUG) -Wall $(INCLUDE) -Winline -pipe
LDFLAGS = -L/usr/local/lib
LDLIBS = -lwiringPi -lm -lcrypt -lrt -lstirshaken

shaken-oob:	main.o
	@echo [link]
	$(CC) -o $@ main.o $(CFLAGS) $(LDFLAGS) $(LDLIBS)

.c.o:
	@echo [CC] $<
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	@echo "[Clean]"
	rm shaken-oob
	rm -f $(OBJ) *~ core tags $(BINS)
