import os
import re
import subprocess as subp
from pwn import *
import argparse

def find_offset(binary_path):
    """
    Finds the offset to the canary by analyzing the stack layout in GDB.
    """
    log.info("Finding offset to canary by analyzing stack layout in GDB...")

    # Prepare GDB commands
    gdb_commands = [
        "set pagination off",
        "break main",
        "run",
        "finish",
        "info frame",
        "info symbol __stack_chk_guard",
        "quit"
    ]

    # Write GDB commands to a script file
    gdb_script_file = "gdb_script.gdb"
    with open(gdb_script_file, "w") as f:
        for cmd in gdb_commands:
            f.write(cmd + "\n")

    # Run GDB with the commands
    gdb_cmd = [
        "gdb-multiarch",
        "-q",
        "--batch",
        "-x", gdb_script_file,
        "--args", "qemu-arm", binary_path
    ]

    try:
        gdb_output = subp.check_output(gdb_cmd, stderr=subp.STDOUT, universal_newlines=True)
        # Debugging: Print GDB output
        # print(f"GDB Output:\n{gdb_output}")

        # Extract the frame information
        frame_info = re.search(r'Stack frame at (0x[0-9a-f]+)', gdb_output)
        if not frame_info:
            log.error("Failed to extract stack frame address.")
            return -1
        frame_addr = int(frame_info.group(1), 16)
        log.info(f"Stack frame address: {hex(frame_addr)}")

        # Extract buffer address
        buffer_info = re.search(r'\$[0-9]+ = \(char \*\) (0x[0-9a-f]+) "<.*>"', gdb_output)
        if not buffer_info:
            log.error("Failed to extract buffer address.")
            return -1
        buffer_addr = int(buffer_info.group(1), 16)
        log.info(f"Buffer address: {hex(buffer_addr)}")

        # Extract canary address
        canary_info = re.search(r'__stack_chk_guard \+0x0 in section \.data at (0x[0-9a-f]+)', gdb_output)
        if not canary_info:
            log.error("Failed to extract canary address.")
            return -1
        canary_addr = int(canary_info.group(1), 16)
        log.info(f"Canary address: {hex(canary_addr)}")

        # Calculate offset
        offset = canary_addr - buffer_addr
        log.success(f"Offset to canary: {offset}")
        return offset

    except Exception as e:
        log.error(f"GDB failed: {e}")
        return -1

def main():
    parser = argparse.ArgumentParser(description="Offset Finder Script by Analyzing Stack")
    parser.add_argument("--binary", required=True, help="Path to the vulnerable binary.")
    args = parser.parse_args()

    log.info(f"Analyzing binary: {args.binary}")

    offset = find_offset(args.binary)

    if offset != -1:
        log.success(f"Offset to canary: {offset} bytes")
    else:
        log.error("Failed to determine offset.")

if __name__ == "__main__":
    main()
