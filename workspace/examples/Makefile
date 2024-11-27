CC = gcc
# CC = arm-linux-gnueabi-gcc
DEFAULT_CFLAGS = -fno-stack-protector -z execstack -no-pie -Wall -Wextra
OUTPUT_DIR = bin

vuln_program_1_CFLAGS = -O0 -g -fno-stack-protector -z execstack -no-pie -Wall -Wextra
# vuln_program_1_CFLAGS = -g -fno-stack-protector -z execstack -no-pie -Wall -Wextra -Wl,-Ttext-segment=0x40000000
vuln_program_2_CFLAGS = -fno-stack-protector -static -no-pie -Wall -Wextra
vuln_program_3_CFLAGS = -fno-stack-protector -z execstack -no-pie -Wall -Wextra -static

PROGRAMS = vuln_program_1 vuln_program_2 vuln_program_3
TARGETS = $(patsubst %,$(OUTPUT_DIR)/%,$(PROGRAMS))

all: $(TARGETS)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

$(OUTPUT_DIR)/vuln_program_1: vuln_program_1.c $(OUTPUT_DIR)
	$(CC) $(vuln_program_1_CFLAGS) -o $@ $<

$(OUTPUT_DIR)/vuln_program_2: vuln_program_2.c $(OUTPUT_DIR)
	$(CC) $(DEFAULT_CFLAGS) $(vuln_program_2_CFLAGS) -o $@ $<

$(OUTPUT_DIR)/vuln_program_3: vuln_program_3.c $(OUTPUT_DIR)
	$(CC) $(vuln_program_3_CFLAGS) -o $@ $<

clean:
	rm -rf $(OUTPUT_DIR)

clean_vuln_program_1:
	rm -f $(OUTPUT_DIR)/vuln_program_1

clean_vuln_program_2:
	rm -f $(OUTPUT_DIR)/vuln_program_2

clean_vuln_program_3:
	rm -f $(OUTPUT_DIR)/vuln_program_3