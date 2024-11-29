# Ice Breaker

Ice Breaker is an automated exploit generation tool (AEG) designed for ARM architectures (AArch32 and AArch64). Leveraging Return Oriented Programming (ROP), Ice Breaker simplifies the process of crafting exploits by automating key stages such as offset detection, writable memory identification, gadget discovery, and payload construction.

## System Requirements

Ice Breaker is containerized using Docker to ensure a consistent and reproducible environment. Ensure you have Docker installed on your system before proceeding.

### Docker

- **Version**: Docker 20.10 or later
- **Installation**: Follow the official Docker installation guide for your operating system: [Docker Installation](https://docs.docker.com/get-docker/)

## Setup

### Building the Docker Image

1. **Clone the Repository**:

    ```bash
    git clone <your-repository-url>
    cd icebreaker
    ```

2. **Build the Docker Image**:

    ```bash
    docker build -t icebreaker .
    ```

    This command builds the Docker image using the provided `Dockerfile` and tags it as `icebreaker`.

### Running the Docker Container

1. **Run the Container**:

    ```bash
    docker run -it --rm -v $(pwd)/workspace:/workspace icebreaker
    ```

    - `-it`: Runs the container in interactive mode with a pseudo-TTY.
    - `--rm`: Automatically removes the container when it exits.
    - `-v $(pwd)/workspace:/workspace`: Mounts the `workspace` directory from your host to `/workspace` inside the container.

2. **Access the Workspace**:

    Once inside the container, navigate to the workspace directory:

    ```bash
    cd /workspace
    ```

    Place your target binaries and scripts within this directory to ensure they are accessible inside the Docker container.

## Usage

Ice Breaker consists of several scripts, each handling a specific stage of the exploit generation process. Below are the scripts along with example usages.

### 1. Offset Finder (`offset_finder.py`)

Determines the exact offset required to overwrite the saved return address in the target binary.

**Example Usage**:

```bash
python3 offset_finder.py --binary /workspace/vulnerable_binary --max_length 2048 --input_method stdin
```

Arguments:

--binary: Path to the target binary.
--max_length: Maximum length of the cyclic pattern (default: 2048).
--input_method: Method of input (stdin or file).

### 2. Writable Memory Finder (`writable_memory_finder.py`)
Identifies writable memory sections (e.g., .bss, .data) in the ELF binary.

Example Usage:
```bash
python3 writable_memory_finder.py --binary /workspace/vulnerable_binary
```

Arguments:

--binary: Path to the target binary.

### 3. Gadget Finder (`find_gadgets.py`)
Extracts ROP gadgets from the binary using the Capstone disassembly framework.

Example Usage:
```bash
python3 find_gadgets.py --binary /workspace/vulnerable_binary
```

Arguments:

--binary: Path to the target binary.

### 4. Exploit Generator (`exploit_generator.py`)
Integrates the findings from the previous scripts to construct the final exploit payload.

Example Usage:
```bash
python3 exploit_generator.py --binary /workspace/vulnerable_binary --arch aarch64 --input_method stdin --padding_file padding --max_length 2048
```

Arguments:

--binary: Path to the target binary.
--arch: Target architecture (arm32 or arm64).
--input_method: Method of input (stdin or file).
--input_arg: Additional argument if needed for the file input method.
--padding_file: Name of the padding file (default: padding).
--keep_file: Flag to keep the padding file after execution (use --keep_file to enable).
--max_length: Maximum length of the cyclic pattern (default: 2048).

## Example Workflow

1. Find the Offset:
```bash
python3 offset_finder.py --binary /workspace/vulnerable_binary --max_length 2048 --input_method stdin
```

2. Identify Writable Memory:
```bash
python3 writable_memory_finder.py --binary /workspace/vulnerable_binary
```

3. Locate ROP Gadgets:
```bash
python3 find_gadgets.py --binary /workspace/vulnerable_binary
```



4. Generate the Exploit:
```bash
python3 exploit_generator.py --binary /workspace/vulnerable_binary --arch aarch64 --input_method stdin --padding_file padding --max_length 2048
```

After running the exploit generator, the payload will be saved to the payload file, with minor adjustment (look at other exploit_generotrs we can execute the program right after this in the script), but I got rid of this feature for debugging and testing purposes. To exploit the binary, use the following command based on the input method:

File input method:
```bash
./vulnerable_binary <input_arg> payload
```

Stdin input method: 
```bash
(cat payload; cat) | ./vulnerable_binary
```

