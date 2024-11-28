import os
import re
import subprocess as subp
from pwn import *
import argparse

DEFAULT_MAX_LENGTH = 1024
DEFAULT_PADDING_FILE = "padding"

def create_padding_file(filename, content):
    """Create or update the padding file with the provided content."""
    with open(filename, "wb") as f:
        f.write(content)
    log.info(f"Padding file '{filename}' created/updated.")

def is_pc_in_pattern(pc, n):
    """Check if the PC value points to a location within the cyclic pattern."""
    try:
        if n == 4:
            pc_bytes = p32(pc)
        elif n == 8:
            pc_bytes = p64(pc)
        else:
            log.error(f"Unsupported word size n={n}.")
            return False

        _ = cyclic_find(pc_bytes[:n], n=n)
        return True
    except ValueError:
        return False

def find_offset(binary_path, 
                n, 
                reg_pc_name,
                max_length=DEFAULT_MAX_LENGTH, 
                input_method='stdin', 
                input_arg=None, 
                breakpoint_func='main',
                padding_file=DEFAULT_PADDING_FILE,
                keep_file=False):
    """
    Finds the offset to overwrite the return address in the vulnerable binary.

    :param binary_path: Path to the binary
    :param n: Size of unique cyclic pattern elements
    :param reg_pc_name: Name of the program counter register (e.g., 'eip' or 'rip')
    :param max_length: Maximum length of the cyclic pattern
    :param input_method: 'stdin' or 'file'
    :param input_arg: Additional arguments if needed for 'file' input method
    :param breakpoint_func: Function name to set breakpoint on
    :param padding_file: Name of the padding file
    :param keep_file: Keep the padding file after execution if True
    :return: Offset to overwrite the return address, or -1 if not found
    """
    low = 0
    high = max_length

    while low < high:
        guess = (low + high) // 2
        padding = cyclic(guess, n=n)

        # Ensure padding file is created/updated
        create_padding_file(padding_file, padding)

        # Prepare GDB commands
        gdb_commands = [
            "set pagination off",
            f"break {breakpoint_func}",
            "run"
        ]

        gdb_commands[2] += f" < {padding_file}"
        
        # Continue execution until crash
        gdb_commands.append("continue")
        # After crash, get PC
        gdb_commands.append(f"info registers {reg_pc_name}")

        # Run GDB with the commands
        gdb_cmd = [
            "gdb", "--batch",
            "--ex", gdb_commands[0],
            "--ex", gdb_commands[1],
            "--ex", gdb_commands[2],
            "--ex", gdb_commands[3],
            "--ex", gdb_commands[4],
            binary_path
        ]

        try:
            gdb_output = subp.run(gdb_cmd, stdout=subp.PIPE, stderr=subp.PIPE, text=True).stdout

            # Debugging: Print GDB output
            print(f"GDB Output:\n{gdb_output}")

            # Extract PC value
            pc_match = re.search(fr'{reg_pc_name}\s+(0x[a-fA-F0-9]+)', gdb_output)
            if not pc_match:
                log.error("Failed to extract PC value from GDB output.")
                return -1

            pc = int(pc_match.group(1), 16)
            log.info(f"Extracted PC: {hex(pc)}")

            # Convert the PC to bytes and find its position in the pattern
            if n == 4:
                pc_bytes = p32(pc)
            elif n == 8:
                pc_bytes = p64(pc)
            else:
                log.error(f"Unsupported word size n={n}.")
                return -1

            try:
                offset = cyclic_find(pc_bytes[:n], n=n)
                log.info(f"Found offset: {offset}")
                return offset
            except ValueError:
                log.warning(f"PC {hex(pc)} not in cyclic pattern. Adjusting search range.")
                # Adjust search range heuristically
                if pc < int.from_bytes(cyclic(guess, n=n)[-n:], "little"):
                    high = guess
                else:
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
                n, 
                reg_pc_name,
                max_length=DEFAULT_MAX_LENGTH, 
                input_method='stdin', 
                input_arg=None, 
                breakpoint_func='main',
                padding_file=DEFAULT_PADDING_FILE,
                keep_file=False):
    """
    Finds the offset to overwrite the return address in the vulnerable binary.

    :param binary_path: Path to the binary
    :param n: Size of unique cyclic pattern elements
    :param reg_pc_name: Name of the program counter register (e.g., 'eip' or 'rip')
    :param max_length: Maximum length of the cyclic pattern
    :param input_method: 'stdin' or 'file'
    :param input_arg: Additional arguments if needed for 'file' input method
    :param breakpoint_func: Function name to set breakpoint on
    :param padding_file: Name of the padding file
    :param keep_file: Keep the padding file after execution if True
    :return: Offset to overwrite the return address, or -1 if not found
    """
    low = 0
    high = max_length

    while low < high:
        guess = (low + high) // 2
        padding = cyclic(guess, n=n)

        # Ensure padding file is created/updated
        create_padding_file(padding_file, padding)

        # Prepare GDB commands
        gdb_commands = [
            "set pagination off",
            f"break {breakpoint_func}",
            "run",
            "handle SIGBUS stop",  # Stop at SIGBUS to inspect registers
            f"info registers {reg_pc_name}",   # Extract PC value
            "continue"             # Continue after inspecting PC
        ]

        if input_arg:
            # If the program requires additional arguments before the file
            gdb_commands[2] += f" {input_arg} {padding_file}"
        else:
            # Pass the padding file as the sole argument
            gdb_commands[2] += f" {padding_file}"

        # Run GDB with the commands
        gdb_cmd = [
            "gdb", "--batch",
            "--ex", gdb_commands[0],
            "--ex", gdb_commands[1],
            "--ex", gdb_commands[2],
            "--ex", gdb_commands[3],
            "--ex", gdb_commands[4],
            binary_path
        ]

        try:
            gdb_output = subp.run(gdb_cmd, stdout=subp.PIPE, stderr=subp.PIPE, text=True).stdout

            # Debugging: Print GDB output
            print(f"GDB Output:\n{gdb_output}")

            # Extract PC value
            pc_match = re.search(fr'{reg_pc_name}\s+(0x[a-fA-F0-9]+)', gdb_output)
            if not pc_match:
                log.error("Failed to extract PC value from GDB output.")
                return -1

            pc = int(pc_match.group(1), 16)
            log.info(f"Extracted PC: {hex(pc)}")

            # Convert the PC to bytes and find its position in the pattern
            if n == 4:
                pc_bytes = p32(pc)
            elif n == 8:
                pc_bytes = p64(pc)
            else:
                log.error(f"Unsupported word size n={n}.")
                return -1

            try:
                offset = cyclic_find(pc_bytes[:n], n=n)
                log.info(f"Found offset: {offset}")
                return offset
            except ValueError:
                log.warning("PC not found in the cyclic pattern. Adjusting search range.")
                # Adjust search range heuristically
                if pc < int.from_bytes(cyclic(guess, n=n)[-n:], "little"):
                    high = guess
                else:
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

def main():
    parser = argparse.ArgumentParser(description="Offset Finder Script")
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

    # Detect architecture and set word size and register name
    elf = ELF(args.binary)
    if elf.bits == 32:
        n = 4
        reg_pc_name = 'eip'
    elif elf.bits == 64:
        n = 8
        reg_pc_name = 'rip'
    else:
        log.error(f"Unsupported architecture with {elf.bits} bits.")
        exit(1)

    # Test offset finding
    log.info(f"Testing offset finding for binary: {args.binary}")
    if args.input_method == 'file':
        offset = find_offset_file(
            binary_path=args.binary,
            n=n,
            reg_pc_name=reg_pc_name,
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
            n=n,
            reg_pc_name=reg_pc_name,
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
