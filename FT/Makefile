CC=gcc

prefix_Idir=..
prefix_Ldir=../install/libs

CFLAGS=-g -I. -I$(prefix_Idir) -I$(prefix_Idir)/src -I$(prefix_Idir)/tests
DEPS = fip_utl.h

LIBS = -Wl,-rpath=../install/lib -Wl,../install/lib/libgcrypt.so
OBJ = driver.o

%.o: %.c $(DEPS)
	$(CC) -g -c -o $@ $< $(CFLAGS)

driver: $(OBJ)
	$(CC) -g -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm *.o || true
	rm driver || true
