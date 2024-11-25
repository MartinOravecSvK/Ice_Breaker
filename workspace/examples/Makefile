CC = gcc
DEFAULT_CFLAGS = -m32 -fno-stack-protector -z execstack -no-pie
OUTPUT_DIR = bin

vuln_program_1_CFLAGS = -m32 -fno-stack-protector -no-pie
vuln_program_2_CFLAGS = -m32 -O0 -fno-stack-protector

PROGRAMS = vuln_program_1 vuln_program_2
TARGETS = $(patsubst %,$(OUTPUT_DIR)/%,$(PROGRAMS))

all: $(OUTPUT_DIR) $(TARGETS)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

$(OUTPUT_DIR)/vuln_program_1: vuln_program_1.c
	$(CC) $(vuln_program_1_CFLAGS) -o $@ $<

$(OUTPUT_DIR)/vuln_program_2: vuln_program_2.c
	$(CC) $(vuln_program_2_CFLAGS) -o $@ $<

clean:
	rm -rf $(OUTPUT_DIR)
