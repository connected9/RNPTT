import argparse
import socket
import threading
import time
import logging
import sys
from typing import List, Dict, Any, Optional
from struct import pack, unpack

# Constants
DEFAULT_TIMEOUT = 1.0  # seconds
MAX_PACKET_SIZE = 65535  # bytes
MAX_PACKET_SIZE_PAYLOAD = MAX_PACKET_SIZE - 28  # Accounting for IP + UDP headers
HEADER_SIZE = 24  # seq_num (8), timestamp (8), hash (8)
SUMMARY_LINES = 7  # Number of lines in summary for real-time updates

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Helper Functions
def validate_port(port: str) -> int:
    port_int = int(port)
    if not (1 <= port_int <= 65535):
        raise argparse.ArgumentTypeError(f"Port must be between 1 and 65535, got {port_int}")
    return port_int

def validate_ip_address(ip: str) -> str:
    try:
        socket.inet_aton(ip)
        return ip
    except socket.error:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {ip}")

def validate_positive_int(value: str, name: str) -> int:
    try:
        val = int(value)
        if val <= 0:
            raise ValueError
        return val
    except ValueError:
        raise argparse.ArgumentTypeError(f"{name} must be a positive integer, got {value}")

def create_payload(size: int) -> bytes:
    return b'\x00' * size

def calculate_hash(payload: bytes) -> int:
    return hash(payload) & 0xFFFFFFFFFFFFFFFF

def pack_packet(seq_num: int, timestamp: float, payload: bytes) -> bytes:
    payload_hash = calculate_hash(payload)
    return pack('!QQQ', seq_num, int(timestamp * 1e6), payload_hash) + payload

def unpack_packet(data: bytes) -> tuple:
    seq_num, timestamp, payload_hash = unpack('!QQQ', data[:24])
    payload = data[24:]
    return seq_num, timestamp / 1e6, payload_hash, len(payload), payload

# Server Class
class Server:
    def __init__(self, host: str, port: int, protocol: str):
        self.host = host
        self.port = port
        self.protocol = protocol.upper()
        self.sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()

    def start(self):
        try:
            if self.protocol == "UDP":
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.bind((self.host, self.port))
                logger.info(f"[UDP Server] Listening on {self.host}:{self.port}")
                self._run_udp()
            else:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.bind((self.host, self.port))
                self.sock.listen(1)
                logger.info(f"[TCP Server] Listening on {self.host}:{self.port}")
                self._run_tcp()
        except Exception as e:
            logger.error(f"[Server] Error: {e}", exc_info=True)
        finally:
            if self.sock:
                self.sock.close()
            logger.info("[Server] Stopped")

    def _run_udp(self):
        while not self._stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(MAX_PACKET_SIZE)
                self.sock.sendto(data, addr)
            except Exception as e:
                if not self._stop_event.is_set():
                    logger.error(f"[UDP Server] Error: {e}")

    def _run_tcp(self):
        while not self._stop_event.is_set():
            try:
                conn, addr = self.sock.accept()
                logger.info(f"[TCP Server] Connection from {addr}")
                with conn:
                    while not self._stop_event.is_set():
                        data = conn.recv(MAX_PACKET_SIZE)
                        if not data:
                            break
                        conn.sendall(data)
            except Exception as e:
                if not self._stop_event.is_set():
                    logger.error(f"[TCP Server] Error: {e}")

# Client Class
class Client:
    def __init__(self, server_ip: str, port: int, packet_size: int, protocol: str, verbose: bool,
                 count: Optional[int] = None, duration_sec: Optional[int] = None, rate: Optional[float] = None):
        self.server_ip = server_ip
        self.port = port
        self.packet_size = packet_size
        self.protocol = protocol.upper()
        self.verbose = verbose
        self.count = count
        self.duration_sec = duration_sec
        self.rate = rate
        self.results: List[Dict[str, Any]] = []
        self.sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()

    def run(self):
        try:
            if self.protocol == "UDP":
                self._run_udp()
            else:
                self._run_tcp()
        except KeyboardInterrupt:
            self._stop_event.set()
            logger.info("Test interrupted by user")

    def _print_summary(self, attempted_packets: int, received_replies: int, is_final_summary: bool):
        lost_packets = attempted_packets - received_replies
        loss_percentage = (lost_packets / attempted_packets * 100) if attempted_packets > 0 else 0

        rtts = [r['rtt'] for r in self.results if r['rtt'] is not None]
        min_rtt_ms = min(rtts) * 1000 if rtts else 0
        max_rtt_ms = max(rtts) * 1000 if rtts else 0
        avg_rtt_ms = (sum(rtts) / len(rtts) * 1000) if rtts else 0

        if rtts:
            mean_rtt = sum(rtts) / len(rtts)
            jitter = sum(abs(rtt - mean_rtt) for rtt in rtts) / len(rtts) if len(rtts) > 1 else 0
        else:
            jitter = 0

        summary_type = '(Final)' if is_final_summary else '(Real-time)'
        lines = [
            f"--- Test Summary {summary_type} ---",
            f"Packets Attempted:  {attempted_packets}",
            f"Packets Replied:    {received_replies}",
            f"Packets Lost:       {lost_packets} ({loss_percentage:.2f}%)",
            f"RTT (ms) Min/Avg/Max: {min_rtt_ms:.3f}/{avg_rtt_ms:.3f}/{max_rtt_ms:.3f}",
            f"Jitter: {jitter*1000:.3f} ms",
            "----------------------------" + "-" * len(summary_type)
        ]

        if not is_final_summary and not self.verbose and attempted_packets > 0:
            sys.stdout.write(f"\033[{SUMMARY_LINES}F")
            for i in range(SUMMARY_LINES):
                sys.stdout.write("\033[K")
                if i < SUMMARY_LINES - 1:
                    sys.stdout.write("\n")
            sys.stdout.write(f"\033[{SUMMARY_LINES}F")

        for line in lines:
            print(line)
        sys.stdout.flush()

    def _run_udp(self):
        attempted_packets = 0
        received_replies_count = 0

        if not self.verbose:
            for _ in range(SUMMARY_LINES): print()

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(DEFAULT_TIMEOUT)
            logger.info(f"[UDP] Target server set to {self.server_ip}:{self.port}")

            start_test_time = time.monotonic()
            last_send_time = start_test_time - (1.0 / self.rate if self.rate else 0)
            seq_num = 0

            while not self._stop_event.is_set():
                current_time = time.monotonic()
                if self.duration_sec and (current_time - start_test_time) >= self.duration_sec:
                    break
                if self.count and seq_num >= self.count:
                    break

                interval = 1.0 / self.rate if self.rate else 0
                time_to_wait = (last_send_time + interval) - current_time
                if time_to_wait > 0:
                    time.sleep(time_to_wait)

                seq_num += 1
                payload = create_payload(self.packet_size)
                timestamp_sent = time.monotonic()
                packet_data = pack_packet(seq_num, timestamp_sent, payload)

                result_entry: Dict[str, Any] = {
                    "packet_num": seq_num, "rtt": None, "status": "Failed", "hash_match": "N/A"
                }

                try:
                    self.sock.sendto(packet_data, (self.server_ip, self.port))
                    last_send_time = timestamp_sent

                    data, addr = self.sock.recvfrom(MAX_PACKET_SIZE_PAYLOAD + HEADER_SIZE + 100)
                    timestamp_received = time.monotonic()

                    echo_seq, echo_ts_orig, echo_hash, echo_payload_len, echo_payload = unpack_packet(data)
                    if echo_seq == seq_num:
                        rtt = timestamp_received - echo_ts_orig
                        hash_match = (calculate_hash(echo_payload) == echo_hash)
                        result_entry.update({
                            "rtt": rtt,
                            "status": "Success",
                            "hash_match": "Yes" if hash_match else "No"
                        })
                        received_replies_count += 1
                    else:
                        result_entry["status"] = "Out-of-order"

                except socket.timeout:
                    result_entry["status"] = "Timeout"
                except socket.error as e:
                    result_entry["status"] = f"Error: {e}"

                self.results.append(result_entry)
                if self.verbose:
                    print(f"Pkt {seq_num}: {result_entry['status']}, RTT={result_entry['rtt']*1000 if result_entry['rtt'] is not None else 'N/A'}ms")

                attempted_packets = seq_num
                if not self._stop_event.is_set():
                    self._print_summary(attempted_packets, received_replies_count, is_final_summary=False)

            self._print_summary(attempted_packets, received_replies_count, is_final_summary=True)

        except Exception as e:
            if not self._stop_event.is_set():
                logger.error(f"[UDP] Client error: {e}", exc_info=True)
        finally:
            if self.sock:
                self.sock.close()
            logger.info(f"[UDP] Client finished. Processed {attempted_packets} packets.")

    def _run_tcp(self):
        attempted_packets = 0
        received_replies_count = 0

        if not self.verbose:
            for _ in range(SUMMARY_LINES): print()

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_ip, self.port))
            logger.info(f"[TCP] Connected to {self.server_ip}:{self.port}")

            start_test_time = time.monotonic()
            seq_num = 0

            while not self._stop_event.is_set():
                current_time = time.monotonic()
                if self.duration_sec and (current_time - start_test_time) >= self.duration_sec:
                    break
                if self.count and seq_num >= self.count:
                    break

                seq_num += 1
                payload = create_payload(self.packet_size)
                timestamp_sent = time.monotonic()
                packet_data = pack_packet(seq_num, timestamp_sent, payload)

                result_entry: Dict[str, Any] = {
                    "packet_num": seq_num, "rtt": None, "status": "Failed", "hash_match": "N/A"
                }

                try:
                    self.sock.sendall(packet_data)
                    data = self.sock.recv(MAX_PACKET_SIZE_PAYLOAD + HEADER_SIZE + 100)
                    timestamp_received = time.monotonic()

                    echo_seq, echo_ts_orig, echo_hash, echo_payload_len, echo_payload = unpack_packet(data)
                    if echo_seq == seq_num:
                        rtt = timestamp_received - echo_ts_orig
                        hash_match = (calculate_hash(echo_payload) == echo_hash)
                        result_entry.update({
                            "rtt": rtt,
                            "status": "Success",
                            "hash_match": "Yes" if hash_match else "No"
                        })
                        received_replies_count += 1
                    else:
                        result_entry["status"] = "Out-of-order"

                except socket.error as e:
                    result_entry["status"] = f"Error: {e}"

                self.results.append(result_entry)
                if self.verbose:
                    print(f"Pkt {seq_num}: {result_entry['status']}, RTT={result_entry['rtt']*1000 if result_entry['rtt'] is not None else 'N/A'}ms")

                attempted_packets = seq_num
                if not self._stop_event.is_set():
                    self._print_summary(attempted_packets, received_replies_count, is_final_summary=False)

                time.sleep(0.01)  # Minimal delay for TCP pacing

            self._print_summary(attempted_packets, received_replies_count, is_final_summary=True)

        except Exception as e:
            if not self._stop_event.is_set():
                logger.error(f"[TCP] Client error: {e}", exc_info=True)
        finally:
            if self.sock:
                self.sock.close()
            logger.info(f"[TCP] Client finished. Processed {attempted_packets} packets.")

# Main Execution
def main():
    parser = argparse.ArgumentParser(
        description="Network Performance Test Tool (Client-Server) for Gaming",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example Usage:

Server Mode:
  python %(prog)s --port 8773 --udp

Client Mode (Gaming Simulation):
  python %(prog)s --server 127.0.0.1 --port 8773 --gaming --udp
  python %(prog)s --server 192.168.1.100 --port 8773 --packet-size 128 --rate 50 --udp
"""
    )
    parser.add_argument("--port", type=validate_port, required=True, help="Port number (1-65535)")

    protocol_group = parser.add_mutually_exclusive_group(required=True)
    protocol_group.add_argument("--tcp", action="store_const", const="tcp", dest="protocol", help="Use TCP protocol")
    protocol_group.add_argument("--udp", action="store_const", const="udp", dest="protocol", help="Use UDP protocol")

    parser.add_argument("--server", type=validate_ip_address, help="Server IP address (Client mode)")
    parser.add_argument("--packet-size", type=lambda x: validate_positive_int(x, "Packet size"), help="Payload size in bytes (Client mode, 1-~65k)")
    parser.add_argument("--rate", type=float, help="Packet sending rate in packets per second (Client mode)")
    parser.add_argument("--gaming", action="store_true", help="Enable gaming mode with default settings (64 bytes, 20 pps, UDP)")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--count", type=lambda x: validate_positive_int(x, "Packet count"), help="Number of packets to send (Client mode)")
    mode_group.add_argument("--time", dest="duration_sec", type=lambda x: validate_positive_int(x, "Test duration"), help="Duration of the test in seconds (Client mode)")

    parser.add_argument("--verbose", action="store_true", help="Print per-packet details (Client mode)")

    args = parser.parse_args()

    is_server_mode = args.server is None

    if is_server_mode:
        if args.packet_size is not None or args.count is not None or args.duration_sec is not None or args.verbose or args.rate is not None or args.gaming:
            parser.error("Arguments --packet-size, --count, --time, --verbose, --rate, --gaming are only for client mode.")
        server = Server(host="0.0.0.0", port=args.port, protocol=args.protocol)
        server.start()
    else:
        if args.packet_size is None and not args.gaming:
            parser.error("Argument --packet-size is required for client mode unless --gaming is used.")
        if args.count is None and args.duration_sec is None:
            parser.error("Either --count or --time must be specified for client mode.")

        if args.gaming:
            args.protocol = "UDP"
            if args.packet_size is None:
                args.packet_size = 64
            if args.rate is None:
                args.rate = 20.0

        client = Client(
            server_ip=args.server,
            port=args.port,
            packet_size=args.packet_size,
            protocol=args.protocol,
            verbose=args.verbose,
            count=args.count,
            duration_sec=args.duration_sec,
            rate=args.rate
        )
        client.run()

if __name__ == "__main__":
    main()