import re
from pwn import *
from elftools.elf.elffile import ELFFile
import subprocess as subp

DEFAULT_BINARY_PATH = "../examples/bin/vuln_program_1"

def find_static_writable_memory(binary_path):
    """
    Identifies writable memory sections (e.g., .bss, .data) in the ELF binary.
    """
    writable_sections = []
    with open(binary_path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            flags = section['sh_flags']
            if flags & 0x2:
                writable_sections.append({
                    "name": section.name,
                    "start": section['sh_addr'],
                    "size": section['sh_size'],
                })
    return writable_sections

def find_dynamic_stack_pointer(binary_path):
    """
    Identifies the stack pointer dynamically using GDB.
    """
    gdb_command = [
        "gdb", "--batch",
        "--ex", "b main",
        "--ex", "run < /dev/null",
        "--ex", "info registers sp",
        binary_path
    ]
    try:
        gdb_output = subp.run(gdb_command, stdout=subp.PIPE, text=True).stdout

        # Debugging: Print GDB output
        print(f"GDB Output:\n{gdb_output}")

        # Locate the stack pointer
        sp_match = re.search(r'sp\s+(0x[a-fA-F0-9]+)', gdb_output)
        if sp_match:
            sp_address = int(sp_match.group(1), 16)
            return sp_address
        else:
            log.error("Failed to locate stack pointer in GDB output.")
            return None

    except Exception as e:
        log.error(f"GDB failed: {e}")
        return None

def analyze_binary(binary_path):
    """
    Analyzes a binary to identify writable memory sections and stack pointer.
    """
    log.info(f"Analyzing binary: {binary_path}")

    # Identify static writable memory sections
    log.info("Identifying static writable memory sections...")
    writable_sections = find_static_writable_memory(binary_path)
    for section in writable_sections:
        log.success(f"Found writable section: {section['name']} - Start: {hex(section['start'])}, Size: {section['size']}")

    if not writable_sections:
        log.warning("No static writable sections found in the binary.")

    # Identify dynamic writable memory (stack pointer)
    log.info("Identifying dynamic writable memory (stack pointer)...")
    sp_address = find_dynamic_stack_pointer(binary_path)
    if sp_address:
        log.success(f"Identified stack pointer address: {hex(sp_address)}")
    else:
        log.warning("Failed to identify stack pointer dynamically.")

    return {
        "writable_sections": writable_sections,
        "stack_pointer": sp_address
    }

if __name__ == "__main__":
    # Test functionality when run directly
    binary_path = DEFAULT_BINARY_PATH
    results = analyze_binary(binary_path)

    # Print summary for standalone testing
    print("\n=== Analysis Results ===")
    if results["writable_sections"]:
        print("Writable Sections:")
        for section in results["writable_sections"]:
            print(f"  - {section['name']} at {hex(section['start'])}, size: {section['size']}")
    else:
        print("No writable sections found.")

    if results["stack_pointer"]:
        print(f"Stack Pointer: {hex(results['stack_pointer'])}")
    else:
        print("Failed to identify stack pointer.")
