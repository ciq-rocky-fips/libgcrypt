CC=gcc
prefix_Idir=./libgcrypt-1.10.0
prefix_Ldir=./libgcrypt-1.10.0/src/.libs
CFLAGS=-g -I. -I$(prefix_Idir) -I$(prefix_Idir)/src -I$(prefix_Idir)/tests
DEPS = fip_utl.h

LIBS = -L$(prefix_Ldir) -lgcrypt
OBJ = driver.o

%.o: %.c $(DEPS)
	$(CC) -g -c -o $@ $< $(CFLAGS)

driver: $(OBJ)
	$(CC) -g -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm *.o || true
	rm test || true
