# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = offload_write_separated

# all source are stored in SRCS-y
SRCS-y := main.c forward.c dpdk_io.c fhash.c memalloc.c diskslave.c memorypool.c

# Build using pkg-config variables if possible
$(shell pkg-config --exists libdpdk)
ifeq ($(.SHELLSTATUS),0)

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PC_FILE := $(shell pkg-config --path libdpdk)
#CFLAGS += -g $(shell pkg-config --cflags libdpdk)
CFLAGS += -DNDEBUG -O3 $(shell pkg-config --cflags libdpdk)
LDFLAGS_SHARED = $(shell pkg-config --libs libdpdk) -lpthread -lrt
LDFLAGS_STATIC = -Wl,-Bstatic $(shell pkg-config --static --libs libdpdk) -lpthread -lrt

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS_SHARED) 

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS_STATIC)

build:
	@mkdir -p $@
.PHONY: print-% 
print-%:
	@echo '$*=$($*)'

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared helper/*.o
	rmdir --ignore-fail-on-non-empty build

else # Build using legacy build system

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, detect a build directory, by looking for a path with a .config
RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))

include $(RTE_SDK)/mk/rte.vars.mk

# CFLAGS += $(WERROR_FLAGS)

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

#EXTRA_CFLAGS += -g -Wfatal-errors -lgmp -lrte_pmd_mlx5
#EXTRA_CFLAGS += -O3 -Wfatal-errors -lgmp

include $(RTE_SDK)/mk/rte.extapp.mk
endif
