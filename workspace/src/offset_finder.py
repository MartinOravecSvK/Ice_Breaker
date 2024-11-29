import os
import re
import subprocess as subp
from pwn import *
import argparse

DEFAULT_MAX_LENGTH = 2048
DEFAULT_PADDING_FILE = "padding"

def create_padding_file(filename, content):
    """Create or update the padding file with the provided content."""
    with open(filename, "wb") as f:
        f.write(content)
    log.info(f"Padding file '{filename}' created/updated.")

def is_value_in_pattern(value, n, bits):
    """Check if the value points to a location within the cyclic pattern."""
    try:
        if bits == 32:
            value &= 0xFFFFFFFF  # Mask to 32 bits
            packed = p32(value)
        else:
            packed = p64(value)
        offset = cyclic_find(packed[:n], n=n)
        return offset
    except ValueError:
        return -1

def get_architecture(binary_path):
    """Get the architecture and bits of the binary."""
    try:
        elf = ELF(binary_path)
        arch = elf.arch
        bits = elf.bits
        return arch, bits
    except Exception as e:
        log.error(f"Failed to parse ELF binary: {e}")
        return None, None

def find_offset(binary_path, 
               max_length=DEFAULT_MAX_LENGTH, 
               input_method='stdin', 
               input_arg=None, 
               breakpoint_func='copyData',
               padding_file=DEFAULT_PADDING_FILE,
               keep_file=False):
    """
    Finds the offset to overwrite the return address in the vulnerable binary.
    """
    arch, bits = get_architecture(binary_path)
    if arch is None or bits is None:
        log.error("Could not determine architecture. Exiting.")
        return -1

    log.info(f"Detected architecture: {arch}, {bits}-bit")

    # Set word size based on architecture
    if bits == 64:
        n = 8
    else:
        n = 4

    # Registers to check based on architecture
    if arch in ['arm', 'thumb', 'aarch64']:
        registers = ['pc', 'lr', 'sp']
    else:
        log.error(f"Unsupported architecture: {arch}")
        return -1

    low = n  # Ensure at least n bytes
    high = max_length

    while low <= high:
        guess = (low + high) // 2
        if guess < n:
            guess = n
        padding = cyclic(guess, n=n)

        # Ensure padding file is created/updated
        create_padding_file(padding_file, padding)

        # Prepare GDB commands
        gdb_commands = [
            "set pagination off",
            "handle SIGSEGV stop",
            "handle SIGBUS stop",
            "run" + (" " + (f"{input_arg} " if input_arg else "") + padding_file if input_method == 'file' else f" < {padding_file}"),
            "info registers pc lr sp",
            "quit"
        ]

        # Run GDB with the commands
        # Use 'gdb-multiarch' for cross-architecture debugging
        gdb_cmd = ["gdb-multiarch", "--batch"]
        for cmd in gdb_commands:
            gdb_cmd.extend(["--ex", cmd])
        gdb_cmd.append(binary_path)

        try:
            gdb_output = subp.run(gdb_cmd, stdout=subp.PIPE, stderr=subp.PIPE, text=True).stdout

            # Debugging: Print GDB output
            print(f"GDB Output:\n{gdb_output}")

            found_offset = -1
            for reg in registers:
                # Extract register value
                reg_match = re.search(rf'{reg}\s+(0x[a-fA-F0-9]+)', gdb_output)
                if reg_match:
                    reg_value = int(reg_match.group(1), 16)
                    log.info(f"Extracted {reg.upper()}: {hex(reg_value)}")

                    offset = is_value_in_pattern(reg_value, n, bits)
                    if offset != -1:
                        log.info(f"Found offset: {offset} (via {reg.upper()})")
                        return offset
                else:
                    log.warning(f"Could not extract {reg.upper()} from GDB output.")
            # No matching register value found, adjust search range
            log.warning("No matching register value found in cyclic pattern. Adjusting search range.")

            # Adjust search range based on PC low byte
            # Assuming little endian
            # Extract PC low byte
            pc_match = re.search(r'pc\s+(0x[a-fA-F0-9]+)', gdb_output)
            if pc_match:
                pc_val = int(pc_match.group(1), 16)
                reg_low_byte = pc_val & 0xFF
                # Get the last byte of the current padding
                sample_last_byte = padding[-1]
                # In Python 3, padding[-1] is already an integer
                sample_last_byte_val = sample_last_byte
                log.info(f"PC low byte: {reg_low_byte}, Pattern last byte: {sample_last_byte_val}")
                if reg_low_byte < sample_last_byte_val:
                    high = guess - 1
                else:
                    low = guess + 1
            else:
                # If no PC match, adjust low
                log.warning("Could not find PC register value, adjusting low.")
                low = guess + 1

        except Exception as e:
            log.error(f"GDB failed: {e}")
            return -1

    if not keep_file:
        try:
            os.remove(padding_file)
            log.info(f"Padding file '{padding_file}' removed.")
        except FileNotFoundError:
            log.warning(f"Padding file '{padding_file}' not found for cleanup.")
    log.error("Offset not found.")
    return -1

def find_offset_file(binary_path, 
                max_length=DEFAULT_MAX_LENGTH, 
                input_method='file', 
                input_arg=None, 
                breakpoint_func='copyData',
                padding_file=DEFAULT_PADDING_FILE,
                keep_file=False):
    """
    Finds the offset to overwrite the return address in the vulnerable binary.
    """
    return find_offset(
        binary_path=binary_path,
        max_length=max_length,
        input_method=input_method,
        input_arg=input_arg,
        breakpoint_func=breakpoint_func,
        padding_file=padding_file,
        keep_file=keep_file
    )

def main():
    parser = argparse.ArgumentParser(description="Offset Finder Script for ARM architectures")
    parser.add_argument("--binary", required=True, help="Path to the vulnerable binary.")
    parser.add_argument("--input-method", choices=['stdin', 'file'], default='stdin', help="Method of input: 'stdin' or 'file'.")
    parser.add_argument("--input-arg", help="Additional argument if needed for 'file' input method.")
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH, help="Maximum length of the cyclic pattern.")
    parser.add_argument("--breakpoint", default='main', help="Function to set breakpoint on.")
    parser.add_argument("--padding-file", default=DEFAULT_PADDING_FILE, help="Name of the padding file.")
    parser.add_argument("--keep-file", action='store_true', help="Keep the padding file after execution.")
    args = parser.parse_args()

    # Validate input arguments
    if args.input_method == 'file' and not args.input_arg:
        log.info("No additional input argument provided for 'file' input method. Assuming only the file name is required.")

    # Test offset finding
    log.info(f"Testing offset finding for binary: {args.binary}")
    if args.input_method == 'file':
        print(
            args.binary,
            args.max_length,
            args.input_method,
            args.input_arg,
            args.breakpoint,
            args.padding_file,
            args.keep_file
        )
        offset = find_offset_file(
            binary_path=args.binary,
            max_length=args.max_length,
            input_method=args.input_method,
            input_arg=args.input_arg,
            breakpoint_func=args.breakpoint,
            padding_file=args.padding_file,
            keep_file=args.keep_file
        )
    else:
        offset = find_offset(
            binary_path=args.binary,
            max_length=args.max_length,
            input_method=args.input_method,
            input_arg=args.input_arg,
            breakpoint_func=args.breakpoint,
            padding_file=args.padding_file,
            keep_file=args.keep_file
        )

    if offset != -1:
        log.success(f"Offset to overwrite return address: {offset}")
    else:
        log.error("Failed to determine offset.")

if __name__ == "__main__":
    main()
