CC = gcc

vuln1_CFLAGS = -fno-stack-protector -static -no-pie -Wall -Wextra

OUTPUT_DIR = bin

PROGRAMS = vuln1
TARGETS = $(patsubst %,$(OUTPUT_DIR)/%,$(PROGRAMS))

all: $(TARGETS)

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

$(OUTPUT_DIR)/vuln1: vuln1.c $(OUTPUT_DIR)
	$(CC) $(vuln1_CFLAGS) -o $@ $<