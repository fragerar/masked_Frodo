COMMON_SOURCES = utils.c random.c xoroshiro128plus.c basics.c
FLAGS = -Wall -Wextra -O3 -march=native
RANLIB=ranlib

ifeq "$(PROF)" "TRUE"
CFLAGS += -pg
endif

ifeq "$(ARCH)" "mps2"
	COMMON_SOURCES += asm_gadgets.s
	include ../pqm4/mk/mps2-an386.mk
	LINKDEPS = ldscript.ld libpqm4hal.a

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

# As we cannot include what we want due to paths wrongly set, we create a dummy
# Makefile that we move into pqm4

HAL.mk:
	cp ../HAL.mk $(SRCDIR)

ldscript.ld: HAL.mk
	make -C ../pqm4 -f HAL.mk obj/ldscript.ld

libpqm4hal.a: HAL.mk
	make -C ../pqm4 -f HAL.mk obj/libpqm4hal.a

endif

# -------------------------------------

utils: $(COMMON_SOURCES) 
	gcc $(FLAGS) -D TESTS_UTILS $(COMMON_SOURCES) -o main  

basics: $(LINKDEPS) $(COMMON_SOURCES)
	$(CC) $(filter-out --specs=%,$(CFLAGS)) -D TESTS_BASICS $(COMMON_SOURCES) $(LDFLAGS) -o main -Wl,--start-group $(LDLIBS) -Wl,--end-group

frodo_gadgets: $(LINKDEPS) $(COMMON_SOURCES) frodo_gadgets.c
	$(CC) $(filter-out --specs=%,$(CFLAGS)) -O3 frodo_gadgets.c -D TEST_FRODO_GADGETS $(COMMON_SOURCES) $(LDFLAGS) -o main -Wl,--start-group $(LDLIBS) -Wl,--end-group

bench: $(COMMON_SOURCES) benchmark.c frodo_gadgets.c basics.h
	$(CC) $(filter-out --specs=%,$(CFLAGS)) -O3 frodo_gadgets.c benchmark.c $(COMMON_SOURCES) $(LDFLAGS) -o bench -Wl,--start-group $(LDLIBS) -Wl,--end-group

#------------------------------------------

# Default params
ifndef $(FRODO_PARAMS)
FRODO_PARAMS=640
endif

ifndef $(MASKING_ORDER)
MASKING_ORDER=1
endif

$(eval N_SHARES=$(shell echo $$(($(MASKING_ORDER)+1))))

CFLAGS += -DFRODO_PARAMS=$(FRODO_PARAMS) -O3
CFLAGS += -D N_SHARES=$(N_SHARES) -D MASKING_ORDER=$(MASKING_ORDER)

objs/%.o: %.c 
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $< -o $@
MASKING_OBJS := objs/basics.o objs/random.o \
	objs/utils.o objs/xoroshiro128plus.o objs/masked_fips202.o

# We create a specific .o for frodo_gadgets.c to be able to call this Makefile multiple times with different parameters set
objs/frodo_gadgets_$(FRODO_PARAMS).o:
	$(CC) -c  $(CFLAGS) frodo_gadgets.c -o objs/frodo_gadgets_$(FRODO_PARAMS).o
MASKING_OBJS += objs/frodo_gadgets_$(FRODO_PARAMS).o

ifeq "$(ARCH)" "mps2"
objs/asm_gadgets.o: asm_gadgets.s 
	$(CC) -c  $(CFLAGS) $< -o $@
MASKING_OBJS += objs/asm_gadgets.o
endif

libmasking: $(LINKDEPS) $(MASKING_OBJS)
	mkdir -p lib

ifeq "$(ARCH)" "mps2"
	$(AR) rcs lib/libmasking$(FRODO_PARAMS).a $(MASKING_OBJS) ../pqm4/obj/libpqm4hal.a
else
	$(AR) rcs lib/libmasking$(FRODO_PARAMS).a $(MASKING_OBJS)
endif
	$(RANLIB) lib/libmasking$(FRODO_PARAMS).a

clean:
	rm -f main 
	rm -f bench
	rm -rf objs obj ../pqm4/obj lib
	rm -f *.d
	rm -f ../pqm4/HAL.mk