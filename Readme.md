
# Network Performance Test Tool

![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)
![Python version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Build status](https://img.shields.io/badge/build-passing-brightgreen.svg)

The **Network Performance Test Tool** is a versatile utility designed to measure network performance between a client and a server using either TCP or UDP protocols. It allows users to test network throughput, latency, and packet loss by sending customizable packets and analyzing the responses. The tool features both a command-line interface (CLI) and a graphical user interface (GUI) for ease of use.

## Features

- **Protocol Support**: Test network performance using TCP or UDP.
- **Customizable Tests**: Configure packet size, number of packets, or test duration.
- **Real-time Feedback**: Monitor test progress with real-time statistics and visualizations (GUI only).
- **Error Handling**: Robust validation and error handling for inputs and network operations.
- **Cross-Platform**: Compatible with Windows and Linux environments.
- **Logging and Results**: Save test results to CSV files for further analysis.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Interface (CLI)](#command-line-interface-cli)
  - [Graphical User Interface (GUI)](#graphical-user-interface-gui)
- [Examples](#examples)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Installation

To use this tool, you need Python 3.8 or higher installed on your system. Follow these steps to set up the environment:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/connected9/RNPTT.git
   cd network-perf-test
   ```

2. **Install Dependencies**:
   The tool uses only standard Python libraries, so no additional dependencies are required. However, for the GUI version, ensure that Tkinter is installed. On most systems, Tkinter is included with Python. If not, you can install it using:
   - **Ubuntu/Debian**:
     ```bash
     sudo apt-get install python3-tk
     ```
   - **Fedora**:
     ```bash
     sudo dnf install python3-tkinter
     ```
   - **Windows**: Tkinter is included with Python installations from [python.org](https://www.python.org/).

3. **Verify Installation**:
   Run the following command to ensure the tool is set up correctly:
   ```bash
   python network_perf_test.py --help
   ```

## Usage

The tool can be used in two modes: **Server Mode** and **Client Mode**. The server must be running before starting the client.

### Command-Line Interface (CLI)

#### Server Mode

To start the server, use the following command:

```bash
python network_perf_test.py --port <PORT> --<PROTOCOL>
```

- `--port`: The port number to listen on (1-65535).
- `--tcp` or `--udp`: Specify the protocol to use.

**Example**:
```bash
python network_perf_test.py --port 8773 --tcp
```

#### Client Mode

To run the client and perform a test, use:

```bash
python network_perf_test.py --server <SERVER_IP> --port <PORT> --packet-size <SIZE> --<MODE> <VALUE> --<PROTOCOL> [--verbose]
```

- `--server`: The IP address of the server.
- `--port`: The port number the server is listening on.
- `--packet-size`: The size of the payload in bytes.
- `--count <NUMBER>`: Number of packets to send.
- `--time <SECONDS>`: Duration of the test in seconds.
- `--tcp` or `--udp`: Specify the protocol to use.
- `--verbose`: Optional flag to print per-packet details.

**Example**:
```bash
python network_perf_test.py --server 127.0.0.1 --port 8773 --packet-size 1024 --count 50 --tcp --verbose
```

### Graphical User Interface (GUI)

To launch the GUI version of the tool, run:

```bash
python network_perf_test_gui.py
```

The GUI provides an intuitive interface to configure and run tests, with real-time visualization of packet statuses using a block-based progress grid.

**Features**:
- Input fields for server IP, port, packet size, protocol, and test mode.
- Real-time progress visualization with color-coded blocks.
- Statistics display for sent packets, received replies, packet loss, and RTT metrics.
- Option to save test results to a CSV file.

## Examples

### CLI Examples

1. **Start TCP Server**:
   ```bash
   python network_perf_test.py --port 8773 --tcp
   ```

2. **Run TCP Client with Count Mode**:
   ```bash
   python network_perf_test.py --server 127.0.0.1 --port 8773 --packet-size 1024 --count 50 --tcp --verbose
   ```

3. **Run UDP Client with Duration Mode**:
   ```bash
   python network_perf_test.py --server 192.168.1.100 --port 8773 --packet-size 512 --time 10 --udp
   ```

### GUI Example

1. **Launch GUI**:
   ```bash
   python network_perf_test_gui.py
   ```

2. **Configure Test**:
   - Enter server IP, port, packet size.
   - Select protocol (TCP/UDP).
   - Choose test mode (Count or Duration) and enter the value.
   - Optionally, check "Verbose" for detailed logging.

3. **Start Test**:
   - Click "Start Test" to begin the test.
   - Monitor progress via the block grid and statistics.
   - Click "Stop Test" to interrupt the test if needed.

## Documentation

For detailed information on the tool's functionality, error handling, and code structure, refer to the following resources:

- **CLI Script**: `network_perf_test.py` - Contains the command-line implementation.
- **GUI Script**: `network_perf_test_gui.py` - Contains the GUI implementation.
- **Logs**: Test results are saved in the `logs/` directory as CSV files.

### Key Features

- **Packet Structure**: Each packet includes a header with sequence number, timestamp, hash, and payload length, followed by the payload.
- **Hash Verification**: Ensures data integrity by comparing the hash of the received payload with the expected hash.
- **Timeout Handling**: Configurable timeout for packet replies to handle network delays.
- **Progress Visualization (GUI)**: A 10x10 grid displays the status of the last 100 packets, with colors indicating different states (e.g., sent, success, timeout).

### Error Handling

The tool includes robust error handling for:

- Invalid inputs (e.g., incorrect IP addresses, port numbers, packet sizes).
- Network errors (e.g., connection refused, timeouts).
- Data integrity issues (e.g., hash mismatches).

Errors are logged appropriately, and user-friendly messages are displayed in the GUI.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes with clear messages.
4. Open a pull request describing your changes.

Please ensure that your code follows the project's coding standards and includes appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
