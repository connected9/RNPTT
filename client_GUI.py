#BY CONNECTED09#
import tkinter as tk
from tkinter import messagebox
import threading
import queue
import time
import socket
import struct
import hashlib
import os
import csv
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# Constants
LOG_DIR = Path("logs")
DEFAULT_TIMEOUT = 2.0  # seconds
HEADER_FORMAT = "!I d 32s I"  # Seq (uint), Timestamp (double), Hash (32 bytes), Payload_Length (uint)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PACKET_SIZE_PAYLOAD = 65535 - HEADER_SIZE - 28  # Approximate max UDP payload

# Helper Functions
def create_payload(size: int) -> bytes:
    """Generates a random payload of the specified size."""
    return os.urandom(size)

def calculate_hash(data: bytes) -> bytes:
    """Calculates SHA256 hash of the given data."""
    return hashlib.sha256(data).digest()

def pack_packet(seq_num: int, timestamp: float, payload: bytes) -> bytes:
    """Packs packet data with header and payload."""
    payload_hash = calculate_hash(payload)
    payload_len = len(payload)
    header = struct.pack(HEADER_FORMAT, seq_num, timestamp, payload_hash, payload_len)
    return header + payload

def unpack_packet(data: bytes) -> tuple:
    """Unpacks packet data into sequence number, timestamp, hash, payload length, and payload."""
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Data too short to unpack header. Expected {HEADER_SIZE}, got {len(data)}.")
    header_data = data[:HEADER_SIZE]
    payload_data = data[HEADER_SIZE:]
    seq_num, timestamp, received_hash, payload_len = struct.unpack(HEADER_FORMAT, header_data)
    return seq_num, timestamp, received_hash, payload_len, payload_data

def validate_ip_address(ip_string: str) -> str:
    """Validates if the string is a valid IP address."""
    try:
        socket.inet_aton(ip_string)
        return ip_string
    except socket.error:
        raise ValueError(f"'{ip_string}' is not a valid IP address.")

def validate_port(port_string: str) -> int:
    """Validates if the string is a valid port number (1-65535)."""
    try:
        port = int(port_string)
        if not (1 <= port <= 65535):
            raise ValueError
        return port
    except ValueError:
        raise ValueError(f"Port must be an integer between 1 and 65535. Got '{port_string}'.")

def validate_positive_int(value_string: str, name: str) -> int:
    """Validates if the string is a positive integer."""
    try:
        value = int(value_string)
        if value <= 0:
            raise ValueError
        return value
    except ValueError:
        raise ValueError(f"{name} must be a positive integer. Got '{value_string}'.")

class NetworkPerfTestGUI(tk.Tk):
    """GUI application for network performance testing with block-based progress visualization."""
    def __init__(self):
        super().__init__()
        self.title("Network Performance Test Client")
        self.geometry("800x600")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.test_thread = None
        self.stop_event = threading.Event()
        self.results = []
        self.results_lock = threading.Lock()
        self.log_queue = queue.Queue()
        self.update_interval = 100  # ms
        self.after_id = None
        self.create_widgets()

    def create_widgets(self):
        """Sets up the GUI widgets."""
        # Input Frame
        input_frame = tk.Frame(self)
        input_frame.pack(pady=10)

        tk.Label(input_frame, text="Server IP:").grid(row=0, column=0, padx=5, pady=5)
        self.server_ip_entry = tk.Entry(input_frame)
        self.server_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        self.server_ip_entry.insert(0, "127.0.0.1")

        tk.Label(input_frame, text="Port:").grid(row=0, column=2, padx=5, pady=5)
        self.port_entry = tk.Entry(input_frame)
        self.port_entry.grid(row=0, column=3, padx=5, pady=5)
        self.port_entry.insert(0, "8773")

        tk.Label(input_frame, text="Packet Size:").grid(row=1, column=0, padx=5, pady=5)
        self.packet_size_entry = tk.Entry(input_frame)
        self.packet_size_entry.grid(row=1, column=1, padx=5, pady=5)
        self.packet_size_entry.insert(0, "1024")

        tk.Label(input_frame, text="Protocol:").grid(row=1, column=2, padx=5, pady=5)
        self.protocol_var = tk.StringVar(value="TCP")
        tk.Radiobutton(input_frame, text="TCP", variable=self.protocol_var, value="TCP").grid(row=1, column=3, padx=5, pady=5)
        tk.Radiobutton(input_frame, text="UDP", variable=self.protocol_var, value="UDP").grid(row=1, column=4, padx=5, pady=5)

        tk.Label(input_frame, text="Test Mode:").grid(row=2, column=0, padx=5, pady=5)
        self.mode_var = tk.StringVar(value="Count")
        tk.Radiobutton(input_frame, text="Count", variable=self.mode_var, value="Count", command=self.update_mode_entries).grid(row=2, column=1, padx=5, pady=5)
        self.count_entry = tk.Entry(input_frame)
        self.count_entry.grid(row=2, column=2, padx=5, pady=5)
        self.count_entry.insert(0, "100")
        tk.Radiobutton(input_frame, text="Duration", variable=self.mode_var, value="Duration", command=self.update_mode_entries).grid(row=2, column=3, padx=5, pady=5)
        self.duration_entry = tk.Entry(input_frame)
        self.duration_entry.grid(row=2, column=4, padx=5, pady=5)
        self.duration_entry.insert(0, "10")
        self.update_mode_entries()

        self.verbose_var = tk.BooleanVar()
        tk.Checkbutton(input_frame, text="Verbose", variable=self.verbose_var).grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.start_button = tk.Button(input_frame, text="Start Test", command=self.start_test)
        self.start_button.grid(row=3, column=2, padx=5, pady=5)
        self.stop_button = tk.Button(input_frame, text="Stop Test", command=self.stop_test, state=tk.DISABLED)
        self.stop_button.grid(row=3, column=3, padx=5, pady=5)

        # Canvas for Blocks
        self.canvas = tk.Canvas(self, width=200, height=200, bg="white")
        self.canvas.pack(pady=10)
        self.block_size = 20
        self.grid_size = 10
        self.blocks = []
        for i in range(self.grid_size):
            for j in range(self.grid_size):
                x0 = j * self.block_size
                y0 = i * self.block_size
                x1 = x0 + self.block_size
                y1 = y0 + self.block_size
                rect = self.canvas.create_rectangle(x0, y0, x1, y1, fill="gray")
                self.blocks.append(rect)

        # Legend
        legend_frame = tk.Frame(self)
        legend_frame.pack(pady=5)
        colors = {"Not Sent": "gray", "Sent": "blue", "Success": "green", "Timeout": "red", "Error": "orange"}
        for idx, (text, color) in enumerate(colors.items()):
            tk.Label(legend_frame, text=text, bg=color, relief="solid", width=10).grid(row=0, column=idx, padx=2)

        # Statistics Frame
        stats_frame = tk.Frame(self)
        stats_frame.pack(pady=10)
        self.sent_label = tk.Label(stats_frame, text="Sent: 0")
        self.sent_label.grid(row=0, column=0, padx=5)
        self.received_label = tk.Label(stats_frame, text="Received: 0")
        self.received_label.grid(row=0, column=1, padx=5)
        self.lost_label = tk.Label(stats_frame, text="Lost: 0")
        self.lost_label.grid(row=0, column=2, padx=5)
        self.loss_percent_label = tk.Label(stats_frame, text="Loss %: 0.00")
        self.loss_percent_label.grid(row=0, column=3, padx=5)
        self.rtt_label = tk.Label(stats_frame, text="RTT Min/Avg/Max: 0.000 / 0.000 / 0.000 ms")
        self.rtt_label.grid(row=1, column=0, columnspan=4, pady=5)

        # Log Text
        self.log_text = tk.Text(self, height=10, state=tk.DISABLED)
        self.log_text.pack(pady=10, fill=tk.BOTH, expand=True)

    def update_mode_entries(self):
        """Enables/disables count and duration entries based on selected mode."""
        mode = self.mode_var.get()
        self.count_entry.config(state=tk.NORMAL if mode == "Count" else tk.DISABLED)
        self.duration_entry.config(state=tk.NORMAL if mode == "Duration" else tk.DISABLED)

    def start_test(self):
        """Initiates the network test after validating inputs."""
        try:
            server_ip = validate_ip_address(self.server_ip_entry.get())
            port = validate_port(self.port_entry.get())
            packet_size = validate_positive_int(self.packet_size_entry.get(), "Packet size")
            protocol = self.protocol_var.get()
            mode = self.mode_var.get()
            count = validate_positive_int(self.count_entry.get(), "Packet count") if mode == "Count" else None
            duration_sec = validate_positive_int(self.duration_entry.get(), "Duration") if mode == "Duration" else None
            verbose = self.verbose_var.get()
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        with self.results_lock:
            self.results.clear()
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.stop_event.clear()
        self.test_thread = threading.Thread(target=self.run_test, args=(server_ip, port, packet_size, protocol, count, duration_sec, verbose))
        self.test_thread.start()
        self.after_id = self.after(self.update_interval, self.update_gui)

    def stop_test(self):
        """Stops the running test and saves results."""
        self.stop_event.set()
        if self.test_thread and self.test_thread.is_alive():
            self.test_thread.join()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_results()
#BY CONNECTED09#

    def run_test(self, server_ip: str, port: int, packet_size: int, protocol: str, count: Optional[int], duration_sec: Optional[int], verbose: bool):
        """Runs the network test in a separate thread."""
        if protocol == "TCP":
            self._run_tcp(server_ip, port, packet_size, count, duration_sec, verbose)
        elif protocol == "UDP":
            self._run_udp(server_ip, port, packet_size, count, duration_sec, verbose)

    def _run_tcp(self, server_ip: str, port: int, packet_size: int, count: Optional[int], duration_sec: Optional[int], verbose: bool):
        """Executes the TCP-based network test."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(DEFAULT_TIMEOUT)
            sock.connect((server_ip, port))
            start_time = time.monotonic()
            seq_num = 0
            while not self.stop_event.is_set():
                seq_num += 1
                if count and seq_num > count:
                    break
                if duration_sec and (time.monotonic() - start_time) >= duration_sec:
                    break
                payload = create_payload(packet_size)
                timestamp_sent = time.monotonic()
                packet_data = pack_packet(seq_num, timestamp_sent, payload)
                result: Dict[str, Any] = {"seq": seq_num, "status": "Sent", "rtt": None, "hash_match": None}
                with self.results_lock:
                    self.results.append(result)
                try:
                    sock.sendall(packet_data)
                    header_bytes = b''
                    while len(header_bytes) < HEADER_SIZE and not self.stop_event.is_set():
                        chunk = sock.recv(HEADER_SIZE - len(header_bytes))
                        if not chunk:
                            raise socket.error("Connection closed by server")
                        header_bytes += chunk
                    if self.stop_event.is_set():
                        break
                    echo_seq, echo_ts, echo_hash, echo_payload_len = struct.unpack(HEADER_FORMAT, header_bytes)
                    payload_bytes = b''
                    while len(payload_bytes) < echo_payload_len and not self.stop_event.is_set():
                        chunk = sock.recv(echo_payload_len - len(payload_bytes))
                        if not chunk:
                            raise socket.error("Connection closed by server")
                        payload_bytes += chunk
                    if self.stop_event.is_set():
                        break
                    timestamp_received = time.monotonic()
                    rtt = timestamp_received - echo_ts
                    hash_match = calculate_hash(payload_bytes) == echo_hash
                    status = "Success" if hash_match else "Error"
                    with self.results_lock:
                        for res in self.results:
                            if res["seq"] == seq_num:
                                res.update({"status": status, "rtt": rtt, "hash_match": hash_match})
                                break
                    if verbose:
                        self.log_queue.put(f"Pkt {seq_num}: RTT={rtt*1000:.3f}ms, Hash: {'OK' if hash_match else 'FAIL'}")
                except socket.timeout:
                    with self.results_lock:
                        for res in self.results:
                            if res["seq"] == seq_num:
                                res["status"] = "Timeout"
                                break
                    if verbose:
                        self.log_queue.put(f"Pkt {seq_num}: Timeout")
                except Exception as e:
                    with self.results_lock:
                        for res in self.results:
                            if res["seq"] == seq_num:
                                res["status"] = f"Error: {e}"
                                break
                    if verbose:
                        self.log_queue.put(f"Pkt {seq_num}: Error ({e})")
                time.sleep(0.01)
        except Exception as e:
            if not self.stop_event.is_set():
                messagebox.showerror("Test Error", f"Failed to run test: {e}")
        finally:
            sock.close()

    def _run_udp(self, server_ip: str, port: int, packet_size: int, count: Optional[int], duration_sec: Optional[int], verbose: bool):
        """Executes the UDP-based network test."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(DEFAULT_TIMEOUT)
            start_time = time.monotonic()
            seq_num = 0
            while not self.stop_event.is_set():
                seq_num += 1
                if count and seq_num > count:
                    break
                if duration_sec and (time.monotonic() - start_time) >= duration_sec:
                    break
                payload = create_payload(packet_size)
                timestamp_sent = time.monotonic()
                packet_data = pack_packet(seq_num, timestamp_sent, payload)
                result: Dict[str, Any] = {"seq": seq_num, "status": "Sent", "rtt": None, "hash_match": None}
                with self.results_lock:
                    self.results.append(result)
                try:
                    sock.sendto(packet_data, (server_ip, port))
                    data, _ = sock.recvfrom(packet_size + HEADER_SIZE + 100)
                    echo_seq, echo_ts, echo_hash, echo_payload_len, echo_payload = unpack_packet(data)
                    timestamp_received = time.monotonic()
                    rtt = timestamp_received - echo_ts
                    hash_match = calculate_hash(echo_payload) == echo_hash
                    status = "Success" if hash_match and echo_seq == seq_num else "Error"
                    with self.results_lock:
                        for res in self.results:
                            if res["seq"] == seq_num:
                                res.update({"status": status, "rtt": rtt, "hash_match": hash_match})
                                break
                    if verbose:
                        self.log_queue.put(f"Pkt {seq_num}: RTT={rtt*1000:.3f}ms, Hash: {'OK' if hash_match else 'FAIL'}")
                except socket.timeout:
                    with self.results_lock:
                        for res in self.results:
                            if res["seq"] == seq_num:
                                res["status"] = "Timeout"
                                break
                    if verbose:
                        self.log_queue.put(f"Pkt {seq_num}: Timeout")
                except Exception as e:
                    with self.results_lock:
                        for res in self.results:
                            if res["seq"] == seq_num:
                                res["status"] = f"Error: {e}"
                                break
                    if verbose:
                        self.log_queue.put(f"Pkt {seq_num}: Error ({e})")
                time.sleep(0.01)
        except Exception as e:
            if not self.stop_event.is_set():
                messagebox.showerror("Test Error", f"Failed to run test: {e}")
        finally:
            sock.close()

    def update_gui(self):
        """Updates the GUI with the latest test results."""
        with self.results_lock:
            for i, res in enumerate(self.results[-100:]):
                index = i % 100
                status = res["status"]
                color = {"Sent": "blue", "Success": "green", "Timeout": "red", "Error": "orange"}.get(status, "gray")
                self.canvas.itemconfig(self.blocks[index], fill=color)
            sent = len(self.results)
            received = sum(1 for r in self.results if r["status"] == "Success")
            lost = sent - received
            loss_percent = (lost / sent * 100) if sent > 0 else 0
            rtts = [r["rtt"] for r in self.results if r["rtt"] is not None]
            min_rtt = min(rtts) * 1000 if rtts else 0
            max_rtt = max(rtts) * 1000 if rtts else 0
            avg_rtt = (sum(rtts) / len(rtts) * 1000) if rtts else 0
        self.sent_label.config(text=f"Sent: {sent}")
        self.received_label.config(text=f"Received: {received}")
        self.lost_label.config(text=f"Lost: {lost}")
        self.loss_percent_label.config(text=f"Loss %: {loss_percent:.2f}")
        self.rtt_label.config(text=f"RTT Min/Avg/Max: {min_rtt:.3f} / {avg_rtt:.3f} / {max_rtt:.3f} ms")
        if self.verbose_var.get():
            while not self.log_queue.empty():
                msg = self.log_queue.get()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, msg + "\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        if not self.stop_event.is_set():
            self.after_id = self.after(self.update_interval, self.update_gui)

    def save_results(self):
        """Saves test results to a CSV file."""
        if not self.results:
            return
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_server_ip = self.server_ip_entry.get().replace('.', '_').replace(':', '_')
        filename = LOG_DIR / f"{safe_server_ip}_{timestamp_str}.csv"
        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ["seq", "rtt_ms", "status", "hash_match"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for res in self.results:
                    row = {
                        "seq": res["seq"],
                        "rtt_ms": f"{res['rtt']*1000:.3f}" if res["rtt"] is not None else "N/A",
                        "status": res["status"],
                        "hash_match": "Yes" if res.get("hash_match") else "No"
                    }
                    writer.writerow(row)
            messagebox.showinfo("Results Saved", f"Results saved to {filename}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save results: {e}")

    def on_closing(self):
        """Handles window close event by stopping the test."""
        self.stop_test()
        self.destroy()

if __name__ == "__main__":
    app = NetworkPerfTestGUI()
    app.mainloop()
    #BY CONNECTED09#
