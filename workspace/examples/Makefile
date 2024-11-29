CC = gcc
CC_32 = arm-linux-gnueabi-gcc
DEFAULT_CFLAGS = -fno-stack-protector -z execstack -no-pie -Wall -Wextra
OUTPUT_DIR = bin

vuln_program_1_CFLAGS = -O0 -g -fno-stack-protector -z execstack -no-pie -Wall -Wextra
vuln_program_2_CFLAGS = -O0 -g -fno-stack-protector -z execstack -no-pie -Wall -Wextra
vuln_program_3_CFLAGS = -fno-stack-protector -z execstack -no-pie -Wall -Wextra -static

PROGRAMS = vuln_program_1 vuln_program_2 vuln_program_3
TARGETS_64 = $(patsubst %,$(OUTPUT_DIR)/%,$(PROGRAMS))
TARGETS_32 = $(patsubst %,$(OUTPUT_DIR)/%32,$(PROGRAMS))

# Default to compiling both architectures
ARCH ?= both

ifeq ($(ARCH),64)
TARGETS = $(TARGETS_64)
else ifeq ($(ARCH),32)
TARGETS = $(TARGETS_32)
else
TARGETS = $(TARGETS_64)
endif

all: $(TARGETS)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

# 64-bit targets
$(OUTPUT_DIR)/vuln_program_1: vuln_program_1.c $(OUTPUT_DIR)
	$(CC) $(vuln_program_1_CFLAGS) -o $@ $<

$(OUTPUT_DIR)/vuln_program_2: vuln_program_2.c $(OUTPUT_DIR)
	$(CC) $(DEFAULT_CFLAGS) $(vuln_program_2_CFLAGS) -o $@ $<

$(OUTPUT_DIR)/vuln_program_3: vuln_program_3.c $(OUTPUT_DIR)
	$(CC) $(vuln_program_3_CFLAGS) -o $@ $<

# 32-bit targets
$(OUTPUT_DIR)/vuln_program_132: vuln_program_1.c $(OUTPUT_DIR)
	$(CC_32) $(vuln_program_1_CFLAGS) -o $@ $<

$(OUTPUT_DIR)/vuln_program_232: vuln_program_2.c $(OUTPUT_DIR)
	$(CC_32) $(DEFAULT_CFLAGS) $(vuln_program_2_CFLAGS) -o $@ $<

$(OUTPUT_DIR)/vuln_program_332: vuln_program_3.c $(OUTPUT_DIR)
	$(CC_32) $(vuln_program_3_CFLAGS) -o $@ $<

clean:
	rm -rf $(OUTPUT_DIR)

clean_vuln_program_1:
	rm -f $(OUTPUT_DIR)/vuln_program_1 $(OUTPUT_DIR)/vuln_program_132

clean_vuln_program_2:
	rm -f $(OUTPUT_DIR)/vuln_program_2 $(OUTPUT_DIR)/vuln_program_232

clean_vuln_program_3:
	rm -f $(OUTPUT_DIR)/vuln_program_3 $(OUTPUT_DIR)/vuln_program_332
