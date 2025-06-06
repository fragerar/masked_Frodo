####  Makefile for compilation on Unix-like operative systems  ####

CC=gcc
ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ARCHITECTURE=_AMD64_
ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
    USE_OPT_LEVEL=_FAST_GENERIC_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
    USE_OPT_LEVEL=_FAST_GENERIC_
else ifeq "$(ARCH)" "PPC"
    ARCHITECTURE=_PPC_
    USE_OPT_LEVEL=_REFERENCE_
else ifeq "$(ARCH)" "s390x"
    ARCHITECTURE=_S390X_
    USE_OPT_LEVEL=_REFERENCE_
else ifeq "$(ARCH)" "mps2"
	ARCHITECTURE=_ARM_
    USE_OPT_LEVEL=_FAST_GENERIC_
endif

ifeq "$(ARCHITECTURE)" "_AMD64_"
    USE_OPT_LEVEL=_FAST_
endif

ifeq "$(OPT_LEVEL)" "REFERENCE"
    USE_OPT_LEVEL=_REFERENCE_
else ifeq "$(OPT_LEVEL)" "FAST_GENERIC"
    USE_OPT_LEVEL=_FAST_GENERIC_
else ifeq "$(OPT_LEVEL)" "FAST"
    ifeq "$(ARCHITECTURE)" "_AMD64_"
        USE_OPT_LEVEL=_FAST_
    endif
endif

USE_GENERATION_A=_AES128_FOR_A_
ifeq "$(GENERATION_A)" "AES128"
    USE_GENERATION_A=_AES128_FOR_A_
else ifeq "$(GENERATION_A)" "SHAKE128"
    USE_GENERATION_A=_SHAKE128_FOR_A_
endif

USING_OPENSSL=_USE_OPENSSL_
ifeq "$(USE_OPENSSL)" "FALSE"
    USING_OPENSSL=NO_OPENSSL
endif

OPENSSL_INCLUDE_DIR=/usr/include
OPENSSL_LIB_DIR=/usr/lib

AR=ar
RANLIB=ranlib
LN=ln -s

VALGRIND_CFLAGS=
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
VALGRIND_CFLAGS= -g -O0 -DDO_VALGRIND_CHECK
endif

ifneq "$(ARCH)" "mps2"
	ifeq "$(EXTRA_CFLAGS)" ""
	CFLAGS= -O3 
	else
	CFLAGS= $(EXTRA_CFLAGS)
	endif
	CFLAGS+= $(VALGRIND_CFLAGS)
	CFLAGS+= -std=gnu11 -Wall -Wextra -DNIX -D $(ARCHITECTURE) -D $(USE_OPT_LEVEL) -D $(USE_GENERATION_A) -D $(USING_OPENSSL)
	ifeq "$(CC)" "gcc"
	ifneq "$(ARCHITECTURE)" "_PPC_"
	ifneq "$(ARCHITECTURE)" "_S390X_"
	ifneq "$(DO_VALGRIND_CHECK)" "TRUE"
	CFLAGS+= -march=native
	endif
	endif
	endif
	endif
	ifeq "$(USE_OPENSSL)" "FALSE"
	LDFLAGS=-lm
	else
	CFLAGS+= -I$(OPENSSL_INCLUDE_DIR)
	LDFLAGS=-lm -L$(OPENSSL_LIB_DIR) -lssl -lcrypto
	endif
endif

ifeq "$(ARCH)" "mps2"
	include ../pqm4/mk/mps2-an386.mk
# --------------------------------------
# We cannot include ../pqm4/mupq/mk/config.mk because of some missing 
# SRCDIR so we copy the relevant flags

SYSROOT := $(shell $(CC) --print-sysroot)
SRCDIR := ../pqm4

CFLAGS += \
	-std=gnu99 \
	--sysroot=$(SYSROOT) \
	-I$(SRCDIR)/common \
	-I$(SRCDIR)/mupq/common \
	-DPQM4

CFLAGS += \
	-O3 -g3 \
	-Wall -Wextra -Wshadow \
	-MMD \
	-fno-common

LDFLAGS += \
	-L$(SRCDIR)/obj \
	-Wl,--gc-sections

LDFLAGS:=$(filter-out -T$(LDSCRIPT),$(LDFLAGS)) -T$(SRCDIR)/$(LDSCRIPT)

# --------------------------------------
	PQM4_OBJS := $(SRCDIR)/obj/common/randombytes.c.o $(SRCDIR)/obj/libpqm4hal.a
	USE_OPENSSL=FALSE
	CFLAGS += -D $(USE_GENERATION_A) -D $(ARCHITECTURE) -D NIX -D $(USE_OPT_LEVEL)
endif

ifeq "$(ARCHITECTURE)" "_AMD64_"
ifeq "$(USE_OPT_LEVEL)" "_FAST_"
CFLAGS += -mavx2 -maes -msse2
endif
endif

ifndef $(MASKING_ORDER)
MASKING_ORDER=1
endif
$(eval N_SHARES=$(shell echo $$(($(MASKING_ORDER)+1))))

ifndef $(KEM_TEST_ITERATIONS)
KEM_TEST_ITERATIONS=10
endif

ifeq "$(MUL_ADD_NAIVE)" "TRUE"
CFLAGS += -D MUL_ADD_NAIVE
endif

ifeq "$(PROF)" "TRUE"
CFLAGS += -pg -D PROF
endif

CFLAGS += -D N_SHARES=$(N_SHARES) -D MASKING_ORDER=$(MASKING_ORDER) -D KEM_TEST_ITERATIONS=$(KEM_TEST_ITERATIONS)

.PHONY: all check clean prettyprint

all: lib640 lib976 lib1344 libmasked640 libmasked976 libmasked1344 simple_tests tests KATS

objs/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/frodo640.o: src/frodo640.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/frodo976.o: src/frodo976.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/frodo1344.o: src/frodo1344.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/masked_frodo640.o: src/masked_frodo640.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/masked_frodo976.o: src/masked_frodo976.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@

objs/masked_frodo1344.o: src/masked_frodo1344.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@


# RAND
ifneq "$(ARCH)" "mps2"
objs/random/random.o: ./random/random.c ./random/random.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ./random/random.c -o objs/random/random.o
RAND_OBJS := objs/random/random.o
endif

# KEM_FRODO
KEM_FRODO640_OBJS := $(addprefix objs/, frodo640.o util.o)
KEM_FRODO640_HEADERS := $(addprefix src/, api_frodo640.h config.h frodo_macrify.h)
$(KEM_FRODO640_OBJS): $(KEM_FRODO640_HEADERS) $(addprefix src/, kem.c noise.c util.c)

KEM_FRODO976_OBJS := $(addprefix objs/, frodo976.o util.o)
KEM_FRODO976_HEADERS := $(addprefix src/, api_frodo976.h config.h frodo_macrify.h)
$(KEM_FRODO976_OBJS): $(KEM_FRODO976_HEADERS) $(addprefix src/, kem.c noise.c util.c)

KEM_FRODO1344_OBJS := $(addprefix objs/, frodo1344.o util.o)
KEM_FRODO1344_HEADERS := $(addprefix src/, api_frodo1344.h config.h frodo_macrify.h)
$(KEM_FRODO1344_OBJS): $(KEM_FRODO1344_HEADERS) $(addprefix src/, masked_kem.c kem.c noise.c util.c)

MASKED_KEM_FRODO640_OBJS := $(addprefix objs/, masked_frodo640.o util.o)
MASKED_KEM_FRODO640_HEADERS := $(addprefix src/, api_masked_frodo640.h config.h frodo_macrify.h masking_interface.h)
$(MASKED_KEM_FRODO640_OBJS): $(MASKED_KEM_FRODO640_HEADERS) $(addprefix src/, masked_kem.c noise.c util.c masking_interface.c)

MASKED_KEM_FRODO976_OBJS := $(addprefix objs/, masked_frodo976.o util.o)
MASKED_KEM_FRODO976_HEADERS := $(addprefix src/, api_masked_frodo976.h config.h frodo_macrify.h masking_interface.h)
$(MASKED_KEM_FRODO976_OBJS): $(MASKED_KEM_FRODO976_HEADERS) $(addprefix src/, masked_kem.c noise.c util.c masking_interface.c)

MASKED_KEM_FRODO1344_OBJS := $(addprefix objs/, masked_frodo1344.o util.o)
MASKED_KEM_FRODO1344_HEADERS := $(addprefix src/, api_masked_frodo1344.h config.h frodo_macrify.h masking_interface.h)
$(MASKED_KEM_FRODO1344_OBJS): $(MASKED_KEM_FRODO1344_HEADERS) $(addprefix src/, masked_kem.c noise.c util.c masking_interface.c)

# AES
ifeq "$(USE_OPENSSL)" "FALSE" 
ifeq "$(USE_OPT_LEVEL)" "_FAST_"
# AES_NI
objs/aes/aes_ni.o: ./aes/aes_ni.c ./aes/aes.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ../common/aes/aes_ni.c -o objs/aes/aes_ni.o
AES_OBJS := objs/aes/aes_ni.o
else
objs/aes/aes_c.o: ./aes/aes_c.c ./aes/aes.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ./aes/aes_c.c -o objs/aes/aes_c.o
AES_OBJS := objs/aes/aes_c.o
endif
else
objs/aes/aes_openssl.o: ./aes/aes_openssl.c ./aes/aes_openssl.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ./aes/aes_openssl.c -o objs/aes/aes_openssl.o
AES_OBJS := objs/aes/aes_openssl.o
endif

# SHAKE
objs/sha3/fips202.o: ./sha3/fips202.c ./sha3/fips202.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ./sha3/fips202.c -o objs/sha3/fips202.o
SHAKE_OBJS := objs/sha3/fips202.o

ifeq "$(USE_OPT_LEVEL)" "_FAST_"
ifeq "$(GENERATION_A)" "SHAKE128"
# SHAKEx4
objs/sha3/fips202x4.o: ./sha3/fips202x4.c ./sha3/fips202x4.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ./sha3/fips202x4.c -o objs/sha3/fips202x4.o

objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o: ./sha3/keccak4x/KeccakP-1600-times4-SIMD256.c ./sha3/keccak4x/KeccakP-1600-times4-SnP.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) ./sha3/keccak4x/KeccakP-1600-times4-SIMD256.c -o objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o

SHAKEx4_OBJS := objs/sha3/fips202x4.o objs/sha3/keccak4x/KeccakP-1600-times4-SIMD256.o
endif
endif

lib640: $(KEM_FRODO640_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf frodo640
	mkdir frodo640
	$(AR) rcs frodo640/libfrodo.a $^
	$(RANLIB) frodo640/libfrodo.a

lib976: $(KEM_FRODO976_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf frodo976
	mkdir frodo976
	$(AR) rcs frodo976/libfrodo.a $^
	$(RANLIB) frodo976/libfrodo.a

lib1344: $(KEM_FRODO1344_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf frodo1344
	mkdir frodo1344
	$(AR) rcs frodo1344/libfrodo.a $^
	$(RANLIB) frodo1344/libfrodo.a

libmasked640: $(MASKED_KEM_FRODO640_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf masked_frodo640
	mkdir masked_frodo640
	make -C ../Masking libmasking ARCH=$(ARCH) FRODO_PARAMS=640 MASKING_ORDER=$(MASKING_ORDER) PROF=$(PROF)
	$(AR) rcsT masked_frodo640/libfrodo.a $(MASKED_KEM_FRODO640_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS) ../Masking/lib/libmasking640.a $(PQM4_OBJS)

libmasked976: $(MASKED_KEM_FRODO976_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf masked_frodo976
	mkdir masked_frodo976
	make -C ../Masking libmasking ARCH=$(ARCH) FRODO_PARAMS=976 MASKING_ORDER=$(MASKING_ORDER) PROF=$(PROF)
	$(AR) rcsT masked_frodo976/libfrodo.a $(MASKED_KEM_FRODO976_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS) ../Masking/lib/libmasking976.a $(PQM4_OBJS)

libmasked1344: $(MASKED_KEM_FRODO1344_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -rf masked_frodo1344
	mkdir masked_frodo1344
	make -C ../Masking libmasking ARCH=$(ARCH) FRODO_PARAMS=1344 MASKING_ORDER=$(MASKING_ORDER) PROF=$(PROF)
	$(AR) rcsT masked_frodo1344/libfrodo.a $(MASKED_KEM_FRODO1344_OBJS) $(RAND_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS) ../Masking/lib/libmasking1344.a $(PQM4_OBJS)

tests: lib640 lib976 lib1344 tests/ds_benchmark.h
	$(CC) $(CFLAGS) -L./frodo640 tests/test_KEM640.c -lfrodo $(LDFLAGS) -o frodo640/test_KEM 
	$(CC) $(CFLAGS) -L./frodo976 tests/test_KEM976.c -lfrodo $(LDFLAGS) -o frodo976/test_KEM 
	$(CC) $(CFLAGS) -L./frodo1344 tests/test_KEM1344.c -lfrodo $(LDFLAGS) -o frodo1344/test_KEM 

simple_tests: libmasked640 libmasked976 libmasked1344
ifeq "$(ARCH)" "mps2"
	$(CC) $(filter-out --specs=%,$(CFLAGS)) tests/test_masked_KEM640.c $(LDFLAGS) -o masked_frodo640/simple_tests -Wl,--start-group $(LDLIBS) -Wl,--end-group ./masked_frodo640/libfrodo.a
	$(CC) $(filter-out --specs=%,$(CFLAGS)) tests/test_masked_KEM976.c $(LDFLAGS) -o masked_frodo976/simple_tests -Wl,--start-group $(LDLIBS) -Wl,--end-group ./masked_frodo976/libfrodo.a
	$(CC) $(filter-out --specs=%,$(CFLAGS)) tests/test_masked_KEM1344.c $(LDFLAGS) -o masked_frodo1344/simple_tests -Wl,--start-group $(LDLIBS) -Wl,--end-group ./masked_frodo1344/libfrodo.a
else
	$(CC) $(CFLAGS) -L./masked_frodo640 tests/test_masked_KEM640.c -lfrodo $(LDFLAGS) -o masked_frodo640/simple_tests 
	$(CC) $(CFLAGS) -L./masked_frodo976 tests/test_masked_KEM976.c -lfrodo $(LDFLAGS) -o masked_frodo976/simple_tests 
	$(CC) $(CFLAGS) -L./masked_frodo1344 tests/test_masked_KEM1344.c -lfrodo $(LDFLAGS) -o masked_frodo1344/simple_tests 
endif

lib640_for_KATs: $(KEM_FRODO640_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	$(AR) rcs frodo640/libfrodo_for_testing.a $^ 
	$(RANLIB) frodo640/libfrodo_for_testing.a

lib976_for_KATs: $(KEM_FRODO976_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	$(AR) rcs frodo976/libfrodo_for_testing.a $^
	$(RANLIB) frodo976/libfrodo_for_testing.a

lib1344_for_KATs: $(KEM_FRODO1344_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	$(AR) rcs frodo1344/libfrodo_for_testing.a $^
	$(RANLIB) frodo1344/libfrodo_for_testing.a

masked_lib640_for_KATs: $(MASKED_KEM_FRODO640_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS) $(MASKING_OBJS)
	$(AR) rcsT masked_frodo640/libfrodo_for_testing.a $^ ../Masking/lib/libmasking640.a
	$(RANLIB) masked_frodo640/libfrodo_for_testing.a

masked_lib976_for_KATs: $(MASKED_KEM_FRODO976_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS) $(MASKING_OBJS)
	$(AR) rcsT masked_frodo976/libfrodo_for_testing.a $^ ../Masking/lib/libmasking976.a
	$(RANLIB) masked_frodo976/libfrodo_for_testing.a

masked_lib1344_for_KATs: $(MASKED_KEM_FRODO1344_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS) $(MASKING_OBJS)
	$(AR) rcsT masked_frodo1344/libfrodo_for_testing.a $^ ../Masking/lib/libmasking1344.a
	$(RANLIB) masked_frodo1344/libfrodo_for_testing.a

KATS: lib640_for_KATs lib976_for_KATs lib1344_for_KATs masked_lib640_for_KATs masked_lib976_for_KATs masked_lib1344_for_KATs
ifeq "$(GENERATION_A)" "SHAKE128"
	$(CC) $(CFLAGS) -L./frodo640 tests/PQCtestKAT_kem640_shake.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o frodo640/PQCtestKAT_kem_shake 
	$(CC) $(CFLAGS) -L./frodo976 tests/PQCtestKAT_kem976_shake.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o frodo976/PQCtestKAT_kem_shake 
	$(CC) $(CFLAGS) -L./frodo1344 tests/PQCtestKAT_kem1344_shake.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o frodo1344/PQCtestKAT_kem_shake 
	$(CC) $(CFLAGS) -L./masked_frodo640 tests/PQCtestKAT_masked_kem640_shake.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o masked_frodo640/PQCtestKAT_kem_shake 
	$(CC) $(CFLAGS) -L./masked_frodo976 tests/PQCtestKAT_masked_kem976_shake.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o masked_frodo976/PQCtestKAT_kem_shake 
	$(CC) $(CFLAGS) -L./masked_frodo1344 tests/PQCtestKAT_masked_kem1344_shake.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o masked_frodo1344/PQCtestKAT_kem_shake 
else
	$(CC) $(CFLAGS) -L./frodo640 tests/PQCtestKAT_kem640.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o frodo640/PQCtestKAT_kem 
	$(CC) $(CFLAGS) -L./frodo976 tests/PQCtestKAT_kem976.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o frodo976/PQCtestKAT_kem 
	$(CC) $(CFLAGS) -L./frodo1344 tests/PQCtestKAT_kem1344.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o frodo1344/PQCtestKAT_kem 
	$(CC) $(CFLAGS) -L./masked_frodo640 tests/PQCtestKAT_masked_kem640.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o masked_frodo640/PQCtestKAT_kem 
	$(CC) $(CFLAGS) -L./masked_frodo976 tests/PQCtestKAT_masked_kem976.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o masked_frodo976/PQCtestKAT_kem 
	$(CC) $(CFLAGS) -L./masked_frodo1344 tests/PQCtestKAT_masked_kem1344.c tests/rng.c -lfrodo_for_testing $(LDFLAGS) -o masked_frodo1344/PQCtestKAT_kem 
endif

check: tests

test640:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 frodo640/test_KEM
else
	frodo640/test_KEM
endif

test976:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 frodo976/test_KEM
else
	frodo976/test_KEM
endif

test1344:
ifeq "$(DO_VALGRIND_CHECK)" "TRUE"
	valgrind --tool=memcheck --error-exitcode=1 --max-stackframe=20480000 frodo1344/test_KEM
else
	frodo1344/test_KEM
endif

clean:
	rm -rf objs *.req frodo640 frodo976 frodo1344 masked_frodo640 masked_frodo976 masked_frodo1344
	rm -f simple_tests simple_tests.elf simple_tests.d simple_tests.bin
	find . -name .DS_Store -type f -delete
	make -C ../Masking clean

prettyprint:
	astyle --style=java --indent=tab --pad-header --pad-oper --align-pointer=name --align-reference=name --suffix=none src/*.h src/*/*.h src/*/*.c
