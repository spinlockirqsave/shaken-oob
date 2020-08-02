CC = gcc
DEBUG = -O0 -ggdb -g
RElease = -O3
INCLUDE = -I/usr/local/include
CFLAGS = $(RELEASE) -Wall $(INCLUDE) -Winline -pipe
LDFLAGS = -L/usr/local/lib
LDLIBS = -lwiringPi -lm -lcrypt -lrt -lstirshaken

shaken-oob:	main.o
	@echo [link]
	$(CC) -o $@ main.o $(LDFLAGS) $(LDLIBS)

.c.o:
	@echo [CC] $<
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	@echo "[Clean]"
	rm -f $(OBJ) *~ core tags $(BINS)
