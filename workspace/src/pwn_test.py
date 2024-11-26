import subprocess as subp
import re
import os
from pwn import *

def create_padding(length, padding_file='padding', n=8):
    """
    Create a file with a cyclic pattern of the specified length.
    """
    padding = cyclic(length, n=n)  # Generates a cyclic pattern
    with open(padding_file, 'wb') as f:
        f.write(padding)
    # Print the first 16 bytes in hex to verify the cyclic pattern
    print(f"Created padding of length {length} with first 16 bytes: {padding[:16].hex()}")

def check_padding(binary_path, padding_file, n=8):
    """
    Use GDB to check if the padding overwrites the return address.
    """
    gdb_command = [
        'gdb', '--batch',
        '--ex', f'run < {padding_file}',
        '--ex', 'info registers pc',  # Get the Program Counter (PC) value
        binary_path
    ]

    try:
        gdb_output = subp.run(
            gdb_command, stdout=subp.PIPE, stderr=subp.PIPE, text=True
        ).stdout
        print(f"GDB Output:\n{gdb_output}")  # Debugging GDB output
    except Exception as e:
        print(f"Error running GDB: {e}")
        return False

    # Extract the PC value from GDB output
    pc_match = re.search(r'pc\s+(0x[a-fA-F0-9]+)', gdb_output)
    if pc_match:
        pc = int(pc_match.group(1), 16)
        print(f"Extracted PC: {hex(pc)}")

        # Convert PC to bytes in little endian
        try:
            pc_bytes = p64(pc)  # For 64-bit ARM
            print(f"PC Bytes (little endian): {pc_bytes.hex()}")
        except OverflowError:
            pc_bytes = p32(pc)  # Adjust based on architecture
            print("Using p32 instead of p64 for PC bytes.")
            print(f"PC Bytes (little endian): {pc_bytes.hex()}")

        # Find the offset using cyclic_find
        try:
            offset = cyclic_find(pc_bytes, n=n)
            print(f"Found offset: {offset}")
            return offset
        except cyclic.CyclicError:
            print("Pattern not found in cyclic pattern.")
            return False

    print("No PC value found in GDB output.")
    return False  # If no match is found

def find_offset(binary_path, n=8, max_length=1024):
    """
    Finds the offset to overwrite the return address in the vulnerable binary.
    """
    padding_file = 'padding'
    low = 0
    high = max_length

    while low < high:
        guess = (low + high) // 2
        create_padding(guess, padding_file, n=n)
        print(f"Testing padding length: {guess}")

        result = check_padding(binary_path, padding_file, n=n)
        if isinstance(result, int):
            os.remove(padding_file)
            return result

        if result:
            high = guess
        else:
            low = guess + 1

    os.remove(padding_file)
    return -1  # Indicate failure

if __name__ == "__main__":
    # Update this with the actual path to your binary
    binary_path = "../examples/bin/vuln_program_1"

    # Determine architecture (32 or 64-bit)
    elf = ELF(binary_path)
    n = 4

    print(f"Finding offset for binary: {binary_path} (Architecture: {elf.bits}-bit)...")
    offset = find_offset(binary_path, n=n)
    if offset != -1:
        print(f"Offset found: {offset}")
    else:
        print("Failed to find the offset.")
