CC=gcc
CFLAGS=-I. -I./miracl -g -O2 -Wall -g -O2 -fno-strict-aliasing -Wno-variadic-macros
LDFLAGS=-L. -L./miracl

LIBS=-lssl -lcrypto -lmiracl -lgmp
DEPS=libmiracl.a
SRC=benchmark.c pbs.c mcl_ecpbs_client.c mcl_ecpbs_bank.c mcl_ecpbs_common.c gmp_pbs_client.c gmp_pbs_bank.c gmp_pbs_common.c

all: benchmark

benchmark: $(SRC) $(DEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(LIBS)

libmiracl.a:
	$(MAKE) -C miracl libmiracl.a

clean:
	$(RM) benchmark *.o
