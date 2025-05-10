#BY CONNECTED09#

import argparse
import socket
import hashlib
import time
import threading
import logging
import csv
import os
import struct
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional
import sys

# --- Constants ---
LOG_DIR = Path("logs")
DEFAULT_TIMEOUT = 2.0  # seconds for individual packet replies
HEADER_FORMAT = "!I d 32s I"  # Seq (uint), Timestamp (double), Hash (32 bytes), Payload_Length (uint)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PACKET_SIZE_PAYLOAD = 65535 - HEADER_SIZE - 28 # Max UDP payload size roughly (IP+UDP headers)
SUMMARY_LINES = 6 # Number of lines printed by _print_summary

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Helper Functions ---
def create_payload(size: int) -> bytes:
    """Generates a payload of a given size."""
    return os.urandom(size)

def calculate_hash(data: bytes) -> bytes:
    """Calculates SHA256 hash of data."""
    return hashlib.sha256(data).digest()

def pack_packet(seq_num: int, timestamp: float, payload: bytes) -> bytes:
    """Packs packet data into bytes including header."""
    payload_hash = calculate_hash(payload)
    payload_len = len(payload)
    header = struct.pack(HEADER_FORMAT, seq_num, timestamp, payload_hash, payload_len)
    return header + payload

def unpack_packet(data: bytes) -> Tuple[int, float, bytes, int, bytes]:
    """Unpacks packet data from bytes. Returns (seq, ts, hash, payload_len, payload)."""
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Data too short to unpack header. Expected {HEADER_SIZE}, got {len(data)}.")
    header_data = data[:HEADER_SIZE]
    payload_data = data[HEADER_SIZE:]
    seq_num, timestamp, received_hash, payload_len_from_header = struct.unpack(HEADER_FORMAT, header_data)
    # Sanity check: does the declared payload length match the actual payload received with this chunk?
    # This is more critical for UDP where 'data' is a single datagram.
    # For TCP, we read payload separately based on payload_len_from_header.
    return seq_num, timestamp, received_hash, payload_len_from_header, payload_data

def validate_ip_address(ip_string: str) -> str:
    """Validates if the given string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_string)
        return ip_string
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{ip_string}' is not a valid IP address.")

def validate_port(port_string: str) -> int:
    """Validates if the given string is a valid port number."""
    try:
        port = int(port_string)
        if not (1 <= port <= 65535):
            raise ValueError
        return port
    except ValueError:
        raise argparse.ArgumentTypeError(f"Port must be an integer between 1 and 65535. Got '{port_string}'.")

def validate_positive_int(value_string: str, name: str) -> int:
    """Validates if the given string is a positive integer."""
    try:
        value = int(value_string)
        if value <= 0:
            raise ValueError
        return value
    except ValueError:
        raise argparse.ArgumentTypeError(f"{name} must be a positive integer. Got '{value_string}'.")

# --- Server ---
class Server: # Assuming Server class is correct from previous iteration or is not the issue here
    """Network performance test server."""
    def __init__(self, host: str, port: int, protocol: str):
        self.host = host
        self.port = port
        self.protocol = protocol.upper()
        self.sock: Optional[socket.socket] = None
        self.running = True

    def _handle_tcp_client(self, conn: socket.socket, addr: Tuple[str, int]):
        """Handles a single TCP client connection."""
        logger.info(f"[TCP] Accepted connection from {addr}")
        try:
            while self.running:
                # Receive header
                header_bytes = b''
                bytes_to_receive_header = HEADER_SIZE
                while len(header_bytes) < bytes_to_receive_header and self.running:
                    chunk = conn.recv(bytes_to_receive_header - len(header_bytes))
                    if not chunk: # Connection closed by client
                        if self.running:
                            logger.info(f"[TCP] Client {addr} disconnected while waiting for header.")
                        return
                    header_bytes += chunk
                
                if not self.running: break # Server shutting down

                # Unpack header to get payload_len
                try:
                    # struct.unpack(HEADER_FORMAT, ...) returns 4 items: seq, ts, hash, payload_len
                    _, _, _, received_payload_len = struct.unpack(HEADER_FORMAT, header_bytes)
                except struct.error as e:
                    logger.error(f"[TCP] Error unpacking header from {addr}: {e}. Received {len(header_bytes)} bytes, expected {HEADER_SIZE}. Data: {header_bytes.hex()}", exc_info=True)
                    return # Stop processing this client

                # Receive payload
                payload_bytes = b''
                bytes_to_receive_payload = received_payload_len # Use the unpacked payload_len
                while len(payload_bytes) < bytes_to_receive_payload and self.running:
                    chunk = conn.recv(bytes_to_receive_payload - len(payload_bytes))
                    if not chunk: # Connection closed unexpectedly
                        if self.running:
                             logger.warning(f"[TCP] Client {addr} disconnected unexpectedly while receiving payload (expected {bytes_to_receive_payload} bytes, got {len(payload_bytes)}).")
                        return
                    payload_bytes += chunk
                
                if not self.running: break # Server shutting down

                # Echo back the original header and the received payload
                conn.sendall(header_bytes + payload_bytes)
                logger.debug(f"[TCP] Echoed {len(header_bytes) + len(payload_bytes)} bytes to {addr}")

        except socket.timeout:
            if self.running: logger.warning(f"[TCP] Socket timeout with client {addr}")
        except ConnectionResetError:
            if self.running: logger.warning(f"[TCP] Connection reset by client {addr} (or server closed due to prior error).")
        except Exception as e:
            if self.running: logger.error(f"[TCP] Unexpected error handling client {addr}: {e}", exc_info=True)
        finally:
            conn.close()
            if self.running : logger.info(f"[TCP] Finished with client {addr}, connection closed.")


    def _run_tcp(self):
        """Runs the TCP server's main listening loop."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.sock.settimeout(1.0) 
            logger.info(f"[TCP] Server listening on {self.host}:{self.port}")

            client_threads = []
            while self.running:
                try:
                    conn, addr = self.sock.accept()
                    client_thread = threading.Thread(target=self._handle_tcp_client, args=(conn, addr))
                    client_thread.daemon = True 
                    client_thread.start()
                    client_threads.append(client_thread)
                except socket.timeout:
                    continue 
                except Exception as e:
                    if self.running: 
                        logger.error(f"[TCP] Error accepting connection: {e}", exc_info=True)
                    break 
            
            for t in client_threads:
                if t.is_alive():
                    t.join(timeout=0.5) 

        except Exception as e:
            if self.running: logger.error(f"[TCP] Server main loop error: {e}", exc_info=True)
        finally:
            if self.sock:
                self.sock.close()
            logger.info("[TCP] Server socket closed.")

    def _run_udp(self):
        """Runs the UDP server's main listening loop."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((self.host, self.port))
            logger.info(f"[UDP] Server listening on {self.host}:{self.port}")
            self.sock.settimeout(1.0)

            while self.running:
                try:
                    data, addr = self.sock.recvfrom(MAX_PACKET_SIZE_PAYLOAD + HEADER_SIZE + 100) 
                    if data:
                        self.sock.sendto(data, addr)
                        logger.debug(f"[UDP] Echoed {len(data)} bytes to {addr}")
                except socket.timeout:
                    continue 
                except Exception as e:
                    if self.running:
                        logger.error(f"[UDP] Error receiving/sending data: {e}", exc_info=True)
        except Exception as e:
            if self.running: logger.error(f"[UDP] Server main loop error: {e}", exc_info=True)
        finally:
            if self.sock:
                self.sock.close()
            logger.info("[UDP] Server socket closed.")

    def start(self):
        """Starts the server based on the chosen protocol in a separate thread."""
        logger.info(f"Attempting to start server in {self.protocol} mode on port {self.port}")
        
        target_method = None
        if self.protocol == "TCP":
            target_method = self._run_tcp
        elif self.protocol == "UDP":
            target_method = self._run_udp
        else:
            logger.error(f"Unsupported protocol: {self.protocol}")
            return

        server_thread = threading.Thread(target=target_method)
        server_thread.daemon = True 
        server_thread.start()
        
        try:
            while server_thread.is_alive():
                time.sleep(0.5) 
        except KeyboardInterrupt:
            logger.info("Ctrl+C received. Shutting down server...")
        finally:
            self.running = False 
            
            if self.sock:
                try:
                    if self.protocol == "TCP" and hasattr(self.sock, '_closed') and not self.sock._closed:
                         self.sock.shutdown(socket.SHUT_RDWR)
                except OSError as e: # NOSONAR
                    logger.debug(f"Socket shutdown error (expected if already closed or not connected): {e}")
                finally: 
                    if hasattr(self.sock, '_closed') and not self.sock._closed:
                        self.sock.close()
            
            if server_thread.is_alive():
                server_thread.join(timeout=2.0) 

            logger.info("Server has stopped.")
#BY CONNECTED09#

# --- Client ---
class Client:
    """Network performance test client."""
    def __init__(self, server_ip: str, port: int, packet_size: int, protocol: str, verbose: bool,
                 count: Optional[int] = None, duration_sec: Optional[int] = None):
        self.server_ip = server_ip
        self.port = port
        self.packet_size = packet_size 
        self.protocol = protocol.upper()
        self.verbose = verbose
        self.count = count
        self.duration_sec = duration_sec
        self.results: List[Dict[str, Any]] = []
        self.sock: Optional[socket.socket] = None
        self._stop_event = threading.Event() 

    def _print_summary(self, attempted_packets: int, received_replies: int, is_final_summary: bool):
        """Prints the summary of the test. Updates in place if not verbose and not final."""
        lost_packets = attempted_packets - received_replies 
        loss_percentage = (lost_packets / attempted_packets * 100) if attempted_packets > 0 else 0
        
        rtts = [r['rtt'] for r in self.results if r['rtt'] is not None]
        min_rtt_ms = min(rtts) * 1000 if rtts else 0
        max_rtt_ms = max(rtts) * 1000 if rtts else 0
        avg_rtt_ms = (sum(rtts) / len(rtts) * 1000) if rtts else 0

        summary_type = '(Final)' if is_final_summary else '(Real-time)'
        
        lines = [
            f"--- Test Summary {summary_type} ---",
            f"Packets Attempted:  {attempted_packets}",
            f"Packets Replied:    {received_replies}",
            f"Packets Lost:       {lost_packets} ({loss_percentage:.2f}%)", 
            f"RTT (ms) Min/Avg/Max: {min_rtt_ms:.3f}/{avg_rtt_ms:.3f}/{max_rtt_ms:.3f}",
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

    def _run_tcp(self):
        """Runs the TCP client test."""
        attempted_packets = 0
        received_replies_count = 0

        if not self.verbose: 
            for _ in range(SUMMARY_LINES): print()
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(DEFAULT_TIMEOUT) 
            self.sock.connect((self.server_ip, self.port))
            logger.info(f"[TCP] Connected to server {self.server_ip}:{self.port}")
            self.sock.settimeout(DEFAULT_TIMEOUT) 

            start_test_time = time.monotonic()
            active_test = True

            while active_test and not self._stop_event.is_set():
                attempted_packets += 1
                seq_num = attempted_packets

                current_time = time.monotonic()
                if self.duration_sec:
                    if (current_time - start_test_time) >= self.duration_sec:
                        logger.debug(f"Test duration ({self.duration_sec}s) reached. Finalizing...")
                        active_test = False; attempted_packets -=1; continue 
                elif self.count:
                    if seq_num > self.count:
                        active_test = False; attempted_packets -=1; continue
                else: 
                    active_test = False; attempted_packets -=1; continue

                payload = create_payload(self.packet_size)
                timestamp_sent = time.monotonic() 
                packet_data = pack_packet(seq_num, timestamp_sent, payload)
                
                result_entry: Dict[str, Any] = {
                    "packet_num": seq_num, "rtt": None, "status": "Failed", "hash_match": "N/A"
                }

                try:
                    self.sock.sendall(packet_data)
                    
                    received_header_bytes = b''
                    bytes_to_receive_header = HEADER_SIZE
                    while len(received_header_bytes) < bytes_to_receive_header:
                        if self._stop_event.is_set(): raise socket.error("Test interrupted by user")
                        chunk = self.sock.recv(bytes_to_receive_header - len(received_header_bytes))
                        if not chunk: raise socket.error("Connection closed prematurely by server (header)")
                        received_header_bytes += chunk
                    
                    # CORRECTED UNPACKING:
                    echo_seq, echo_ts_orig, echo_hash_orig, echo_payload_len_from_header = struct.unpack(HEADER_FORMAT, received_header_bytes)

                    received_payload_bytes = b''
                    bytes_to_receive_payload = echo_payload_len_from_header # Use the length from the echoed header
                    while len(received_payload_bytes) < bytes_to_receive_payload:
                        if self._stop_event.is_set(): raise socket.error("Test interrupted by user")
                        chunk = self.sock.recv(bytes_to_receive_payload - len(received_payload_bytes))
                        if not chunk: raise socket.error("Connection closed prematurely by server (payload)")
                        received_payload_bytes += chunk

                    timestamp_received = time.monotonic()
                    
                    received_replies_count += 1
                    rtt = timestamp_received - echo_ts_orig # RTT based on original timestamp from echoed header
                    
                    recalculated_hash = calculate_hash(received_payload_bytes) # Hash of the echoed payload
                    hash_match = (recalculated_hash == echo_hash_orig) # Compare with hash from echoed header

                    result_entry.update({
                        "rtt": rtt,
                        "status": "Success",
                        "hash_match": "Yes" if hash_match else "No"
                    })

                    if self.verbose:
                        print(f"Pkt {seq_num}: RTT={rtt*1000:.3f}ms, Hash Match: {'Yes' if hash_match else 'No'}")
                
                except socket.timeout:
                    result_entry["status"] = "Timeout"
                    if self.verbose: print(f"Pkt {seq_num}: Timeout receiving reply")
                except struct.error as e: # Catch struct unpacking errors specifically
                    result_entry["status"] = f"Error: Header unpack failed ({e})"
                    if self.verbose: print(f"Pkt {seq_num}: Header unpack error ({e})")
                    if not self._stop_event.is_set():
                        logger.error(f"[TCP] Error unpacking received header for packet {seq_num}: {e}", exc_info=True)
                    active_test = False
                except socket.error as e: 
                    result_entry["status"] = f"Error: {e}"
                    if self.verbose: print(f"Pkt {seq_num}: Socket Error ({e})")
                    if not self._stop_event.is_set(): 
                        logger.error(f"[TCP] Socket error during packet {seq_num}: {e}", exc_info=True)
                    active_test = False 
                
                self.results.append(result_entry)
                if not self._stop_event.is_set():
                    self._print_summary(attempted_packets, received_replies_count, is_final_summary=False)
                
                if not active_test: break 
                time.sleep(0.01)

            self._print_summary(attempted_packets, received_replies_count, is_final_summary=True)

        except socket.gaierror:
            logger.error(f"[TCP] Could not resolve hostname: {self.server_ip}")
        except ConnectionRefusedError:
            logger.error(f"[TCP] Connection refused by server {self.server_ip}:{self.port}")
        except socket.timeout: 
            logger.error(f"[TCP] Connection timed out to server {self.server_ip}:{self.port}")
        except socket.error as e: 
            if not self._stop_event.is_set():
                 logger.error(f"[TCP] Socket error (pre-loop or critical): {e}", exc_info=True)
        except Exception as e:
            if not self._stop_event.is_set():
                logger.error(f"[TCP] Client error: {e}", exc_info=True)
        finally:
            if self.sock: self.sock.close()
            if not self._stop_event.is_set(): 
                logger.info(f"[TCP] Client finished. Processed {attempted_packets} packets.")

    def _run_udp(self):
        """Runs the UDP client test."""
        attempted_packets = 0
        received_replies_count = 0

        if not self.verbose:
            for _ in range(SUMMARY_LINES): print()
            
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.connect((self.server_ip, self.port)) 
            logger.info(f"[UDP] Target server set to {self.server_ip}:{self.port}")
            self.sock.settimeout(DEFAULT_TIMEOUT)

            start_test_time = time.monotonic()
            active_test = True

            while active_test and not self._stop_event.is_set():
                attempted_packets += 1
                seq_num = attempted_packets

                current_time = time.monotonic()
                if self.duration_sec:
                    if (current_time - start_test_time) >= self.duration_sec:
                        logger.debug(f"Test duration ({self.duration_sec}s) reached. Finalizing...")
                        active_test = False; attempted_packets -=1; continue
                elif self.count:
                    if seq_num > self.count:
                        active_test = False; attempted_packets -=1; continue
                else:
                    active_test = False; attempted_packets -=1; continue
                
                payload = create_payload(self.packet_size)
                timestamp_sent = time.monotonic()
                packet_data = pack_packet(seq_num, timestamp_sent, payload)
            
                result_entry: Dict[str, Any] = {
                    "packet_num": seq_num, "rtt": None, "status": "Failed", "hash_match": "N/A"
                }

                try:
                    self.sock.send(packet_data) 

                    data_received_udp = self.sock.recv(self.packet_size + HEADER_SIZE + 100) 
                    timestamp_received = time.monotonic()
                    
                    # Use the robust unpack_packet which handles length check internally for header part
                    echo_seq, echo_ts_orig, echo_hash_orig, echo_payload_len_from_header, echo_payload_data = unpack_packet(data_received_udp)
                    
                    # For UDP, the payload comes with the header, so check if its length matches the header's claim
                    if len(echo_payload_data) != echo_payload_len_from_header:
                        logger.warning(f"[UDP] Pkt {seq_num}: Received payload length {len(echo_payload_data)} does not match header's claim {echo_payload_len_from_header}.")
                        result_entry["status"] = "Error: Payload Length Mismatch"
                        # Potentially stop here or mark hash as N/A if we don't trust the payload
                        # For now, continue with hash check on what was received.
                    
                    received_replies_count += 1
                    rtt = timestamp_received - echo_ts_orig
                    
                    recalculated_hash = calculate_hash(echo_payload_data)
                    hash_match = (recalculated_hash == echo_hash_orig)

                    # Update status only if it wasn't already an error like "Payload Length Mismatch"
                    if result_entry["status"] == "Failed": # Default status
                        result_entry["status"] = "Success"
                    if echo_seq != seq_num and result_entry["status"] == "Success":
                        result_entry["status"] = "Success (Seq Mismatch)"


                    result_entry.update({
                        "rtt": rtt,
                        "hash_match": "Yes" if hash_match else "No"
                    })


                    if self.verbose:
                        status_detail = ""
                        if echo_seq != seq_num: status_detail += ", Seq Mismatch!"
                        if not hash_match: status_detail += ", Hash Mismatch!"
                        if len(echo_payload_data) != echo_payload_len_from_header: status_detail += ", Payload Len Mismatch!"
                        print(f"Pkt {seq_num}: RTT={rtt*1000:.3f}ms, Hash: {'OK' if hash_match else 'FAIL'}{status_detail}")

                except ValueError as e: # From unpack_packet if data is too short
                    result_entry["status"] = f"Error: Unpack failed ({e})"
                    if self.verbose: print(f"Pkt {seq_num}: Unpack error ({e})")
                    if not self._stop_event.is_set():
                        logger.error(f"[UDP] Error unpacking received datagram for packet {seq_num}: {e}", exc_info=True)
                except socket.timeout:
                    result_entry["status"] = "Timeout"
                    if self.verbose: print(f"Pkt {seq_num}: Timeout (reply lost)")
                except ConnectionRefusedError as e: 
                    result_entry["status"] = f"Error: Port Unreachable?"
                    if self.verbose: print(f"Pkt {seq_num}: Connection Refused ({e})")
                    if not self._stop_event.is_set():
                        logger.warning(f"[UDP] Connection refused for packet {seq_num}: {e}. Server might not be listening or firewall.")
                except socket.error as e:
                    result_entry["status"] = f"Error: {e}"
                    if self.verbose: print(f"Pkt {seq_num}: Socket Error ({e})")
                    if not self._stop_event.is_set():
                        logger.error(f"[UDP] Socket error during packet {seq_num}: {e}", exc_info=True)
                
                self.results.append(result_entry)
                if not self._stop_event.is_set():
                    self._print_summary(attempted_packets, received_replies_count, is_final_summary=False)
                
                if not active_test: break
                time.sleep(0.01)

            self._print_summary(attempted_packets, received_replies_count, is_final_summary=True)

        except socket.gaierror:
             logger.error(f"[UDP] Could not resolve hostname: {self.server_ip}")
        except ConnectionRefusedError: 
            logger.error(f"[UDP] Initial connection refused by {self.server_ip}:{self.port}. Server down or port blocked.")
        except socket.error as e:
            if not self._stop_event.is_set():
                logger.error(f"[UDP] Socket error (pre-loop or critical): {e}", exc_info=True)
        except Exception as e:
            if not self._stop_event.is_set():
                logger.error(f"[UDP] Client error: {e}", exc_info=True)
        finally:
            if self.sock: self.sock.close()
            if not self._stop_event.is_set():
                logger.info(f"[UDP] Client finished. Processed {attempted_packets} packets.")
#BY CONNECTED09#

    def run(self):
        """Runs the client test and saves results."""
        self._stop_event.clear()

        mode_info = ""
        if self.count:
            mode_info = f"Packets: {self.count}"
        elif self.duration_sec:
            mode_info = f"Duration: {self.duration_sec}s"
        
        logger.info(f"Starting client test to {self.server_ip}:{self.port} ({self.protocol})")
        logger.info(f"{mode_info}, Payload Size: {self.packet_size} bytes")

        if self.packet_size > MAX_PACKET_SIZE_PAYLOAD and self.protocol == "UDP":
            logger.warning(
                f"Packet payload size {self.packet_size} for UDP may lead to IP fragmentation or packet drop. "
                f"Recommended max payload: {MAX_PACKET_SIZE_PAYLOAD} bytes (actual IP MTU dependent)."
            )
        
        try:
            if self.protocol == "TCP":
                self._run_tcp()
            elif self.protocol == "UDP":
                self._run_udp()
            else:
                logger.error(f"Unsupported protocol: {self.protocol}")
                return
        except KeyboardInterrupt:
            logger.info("Client test interrupted by user (Ctrl+C). Finalizing...")
            self._stop_event.set() 
        finally:
            if self.results: 
                self.save_results()
            else:
                logger.info("No results to save (test may have been interrupted very early or failed to start).")
            logger.info("Client run method finished.")


    def save_results(self):
        """Saves test results to a CSV file."""
        if not self.results: 
            logger.info("Save results: No results to write.")
            return
            
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_server_ip = self.server_ip.replace('.', '_').replace(':', '_') 
        filename = LOG_DIR / f"{safe_server_ip}_{timestamp_str}.csv"
        
        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ["packet_num", "rtt_ms", "status", "hash_match"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for res in self.results:
                    row_to_write = {
                        "packet_num": res["packet_num"],
                        "rtt_ms": f"{res['rtt']*1000:.3f}" if res["rtt"] is not None else "N/A",
                        "status": res["status"],
                        "hash_match": res["hash_match"]
                    }
                    writer.writerow(row_to_write)
            logger.info(f"Results saved to {filename}")
        except IOError as e:
            logger.error(f"Failed to save results to {filename}: {e}", exc_info=True)

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(
        description="Network Performance Test Tool (Client-Server)",
        formatter_class=argparse.RawTextHelpFormatter, 
        epilog="""Example Usage:

Server Mode:
  python %(prog)s --port 8773 --tcp
  python %(prog)s --port 8773 --udp

Client Mode (Count-based):
  python %(prog)s --server 127.0.0.1 --port 8773 --packet-size 1024 --count 50 --tcp --verbose
  python %(prog)s --server 192.168.1.100 --port 8773 --packet-size 512 --count 100 --udp

Client Mode (Time-based):
  python %(prog)s --server 127.0.0.1 --port 8773 --packet-size 64 --time 10 --tcp
  python %(prog)s --server 127.0.0.1 --port 8773 --packet-size 1400 --time 5 --udp --verbose
"""
    )
    parser.add_argument("--port", type=validate_port, required=True, help="Port number (1-65535)")
    
    protocol_group = parser.add_mutually_exclusive_group(required=True)
    protocol_group.add_argument("--tcp", action="store_const", const="tcp", dest="protocol", help="Use TCP protocol")
    protocol_group.add_argument("--udp", action="store_const", const="udp", dest="protocol", help="Use UDP protocol")

    parser.add_argument("--server", type=validate_ip_address, help="Server IP address (Client mode)")
    parser.add_argument("--packet-size", type=lambda x: validate_positive_int(x, "Packet size"), help="Payload size in bytes (Client mode, 1-~65k)")
    
    mode_group = parser.add_mutually_exclusive_group() 
    mode_group.add_argument("--count", type=lambda x: validate_positive_int(x, "Packet count"), help="Number of packets to send (Client mode)")
    mode_group.add_argument("--time", dest="duration_sec", type=lambda x: validate_positive_int(x, "Test duration"), help="Duration of the test in seconds (Client mode)")
    
    parser.add_argument("--verbose", action="store_true", help="Print per-packet details (Client mode)")

    args = parser.parse_args()

    is_server_mode = args.server is None

    if is_server_mode:
        if args.packet_size is not None or args.count is not None or args.duration_sec is not None or args.verbose:
            parser.error("Arguments --packet-size, --count, --time, --verbose are only for client mode.")
        
        server = Server(host="0.0.0.0", port=args.port, protocol=args.protocol)
        server.start()
    else: 
        if args.packet_size is None:
            parser.error("Argument --packet-size is required for client mode.")
        if args.count is None and args.duration_sec is None:
            parser.error("Either --count or --time must be specified for client mode.")
        
        if args.packet_size <= 0:
             parser.error("Packet size must be a positive integer.")
        if args.packet_size > MAX_PACKET_SIZE_PAYLOAD + HEADER_SIZE : 
            logger.warning(f"Total packet size (header + payload) may exceed common MTU, especially for UDP. Payload: {args.packet_size}, Header: {HEADER_SIZE}")


        client = Client(
            server_ip=args.server,
            port=args.port,
            packet_size=args.packet_size,
            protocol=args.protocol,
            verbose=args.verbose,
            count=args.count,
            duration_sec=args.duration_sec
        )
        client.run()

if __name__ == "__main__":
    #BY CONNECTED09#

    main()
