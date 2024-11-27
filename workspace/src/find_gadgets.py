import os
from elftools.elf.elffile import ELFFile
from capstone import *
import argparse

def locate_gadgets(binary_path):
    """Extract gadgets from the binary."""
    gadgets = {}
    md = Cs(CS_ARCH_AARCH64, CS_MODE_ARM)
    md.detail = True

    with open(binary_path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if section.name == ".text":
                code = section.data()
                base_addr = section["sh_addr"]
                for insn in md.disasm(code, base_addr):
                    if insn.mnemonic == "ret":
                        gadget = extract_gadget(md, code, base_addr, insn)
                        if gadget:
                            gadgets.update(gadget)
    return gadgets

def extract_gadget(md, code, base_addr, insn):
    """Extract a single gadget based on a return instruction."""
    offset = insn.address - base_addr
    start = max(0, offset - 16)
    gadget_bytes = code[start:offset]
    gadget_insns = list(md.disasm(gadget_bytes, base_addr + start))[::-1]
    mapping = {}

    for gadget_insn in gadget_insns:
        # Load/Store
        if gadget_insn.mnemonic == "ldp" and "x0" in gadget_insn.op_str and "x1" in gadget_insn.op_str:
            mapping["ldp x0, x1; ret"] = gadget_insn.address
        elif gadget_insn.mnemonic == "ldp" and "x1" in gadget_insn.op_str and "x2" in gadget_insn.op_str:
            mapping["ldp x1, x2; ret"] = gadget_insn.address
        elif gadget_insn.mnemonic == "ldr" and "[sp]" in gadget_insn.op_str:
            if "x0" in gadget_insn.op_str:
                mapping["ldr x0, [sp], #8 ; ret"] = gadget_insn.address
            elif "x8" in gadget_insn.op_str:
                mapping["ldr x8, [sp], #8 ; ret"] = gadget_insn.address
        elif gadget_insn.mnemonic == "str" and "x1" in gadget_insn.op_str and "[x0]" in gadget_insn.op_str:
            mapping["str x1, [x0]; ret"] = gadget_insn.address
        
        # Arithmetic
        elif gadget_insn.mnemonic == "add" and "x0" in gadget_insn.op_str:
            mapping["add x0, x1, x2 ; ret"] = gadget_insn.address
        elif gadget_insn.mnemonic == "sub" and "x3" in gadget_insn.op_str:
            mapping["sub x3, x4, x5 ; r et"] = gadget_insn.address

        # System Call
        elif gadget_insn.mnemonic == "svc" and "#0" in gadget_insn.op_str:
            mapping["svc #0"] = gadget_insn.address

        # Branching
        elif gadget_insn.mnemonic == "br" and "x16" in gadget_insn.op_str:
            mapping["br x16 ; ret"] = gadget_insn.address

    return mapping

def main():
    parser = argparse.ArgumentParser(description="Extract gadgets from an ARM64 binary.")
    parser.add_argument("--binary", help="Path to the binary to analyze.")
    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"Error: Binary '{args.binary}' does not exist.")
        return

    print(f"Analyzing binary: {args.binary}")
    gadgets = locate_gadgets(args.binary)

    if not gadgets:
        print("No gadgets found in the binary.")
        return

    print("\n=== Extracted Gadgets ===")
    for gadget, addr in gadgets.items():
        print(f"  - {gadget}: {hex(addr)}")

if __name__ == "__main__":
    main()
