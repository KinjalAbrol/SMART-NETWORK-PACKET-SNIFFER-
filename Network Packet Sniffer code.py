import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap, raw, Ether
from collections import defaultdict, deque
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
import subprocess
import platform

# ---------------- Global Variables ----------------
ip_counter = defaultdict(int)
captured_packets = []
sniffing = False
protocol_filter = "ip"
packet_rate = deque(maxlen=50)
timestamps = deque(maxlen=50)
suspicious_ips = set()
iot_devices = {"192.168.1.10", "192.168.1.20"}  # Example IoT device IPs
mac_table = {}  # Store IP-to-MAC mapping
iot_warned = set()  # To ensure popup shows only once per IoT device

# ---------------- Protocol Detection ----------------
def detect_protocol(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(IP):
        return "IP"
    else:
        return "Unknown"

# ---------------- Cross-platform IP Block ----------------
def block_ip(ip):
    if ip not in suspicious_ips:
        suspicious_ips.add(ip)
        try:
            system = platform.system()
            if system == "Linux":
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif system == "Windows":
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"
                ], check=True)
            messagebox.showwarning("Mitigation", f"🚨 Suspicious IP blocked: {ip}")
        except Exception as e:
            # Fallback: simulate blocking in Python
            messagebox.showerror("Error", f"Failed to block IP {ip} at OS-level.\nIt will be ignored in sniffer.\n{e}")

def unblock_ip(ip):
    if ip in suspicious_ips:
        suspicious_ips.remove(ip)
        try:
            system = platform.system()
            if system == "Linux":
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif system == "Windows":
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=Block_{ip}", "remoteip={ip}"
                ], check=True)
            messagebox.showinfo("Unblocked", f"✅ IP unblocked: {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unblock IP {ip} at OS-level.\n{e}")

# ---------------- IoT Anomaly Detection (Single Popup) ----------------
def detect_iot_anomaly(ip, count):
    if ip in iot_devices and count > 1000 and ip not in iot_warned:
        iot_warned.add(ip)
        response = messagebox.askyesno(
            "IoT Alert",
            f"⚠️ IoT Device {ip} unusual traffic detected!\nDo you want to block it?"
        )
        if response:
            block_ip(ip)

# ---------------- Update IP Table ----------------
def update_table():
    for row in ip_tree.get_children():
        ip_tree.delete(row)
    for ip, count in ip_counter.items():
        mac = mac_table.get(ip, "Unknown")
        ip_tree.insert("", "end", values=(ip, mac, count))

# ---------------- Update Packet List ----------------
def update_packet_list(packet):
    proto = detect_protocol(packet)
    src_port = packet.sport if hasattr(packet, "sport") else "-"
    dst_port = packet.dport if hasattr(packet, "dport") else "-"
    mac_src = packet[Ether].src if packet.haslayer(Ether) else "N/A"
    mac_dst = packet[Ether].dst if packet.haslayer(Ether) else "N/A"
    packet_list.insert(
        tk.END,
        f"[{proto}] {packet.summary()} (Src Port: {src_port}, Dst Port: {dst_port}, Src MAC: {mac_src}, Dst MAC: {mac_dst})"
    )
    packet_list.yview(tk.END)

# ---------------- Process Each Packet ----------------
def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Ignore blocked IPs
        if src_ip in suspicious_ips:
            return

        ip_counter[src_ip] += 1
        ip_counter[dst_ip] += 1
        captured_packets.append(packet)

        # Store MAC address if available
        if packet.haslayer(Ether):
            mac_table[src_ip] = packet[Ether].src
            mac_table[dst_ip] = packet[Ether].dst

        update_table()
        update_packet_list(packet)

        detect_iot_anomaly(src_ip, ip_counter[src_ip])

        if ip_counter[src_ip] > 100:
            block_ip(src_ip)

        now = time.time()
        if not timestamps or now - timestamps[-1] >= 1:
            timestamps.append(now)
            packet_rate.append(len(captured_packets))
            update_graph()

# ---------------- Show Packet Details ----------------
def show_packet_details(event):
    selection = packet_list.curselection()
    if not selection:
        return
    index = selection[0]
    packet = captured_packets[index]

    details = []
    proto = detect_protocol(packet)
    details.append(f"Detected Protocol: {proto}")

    if packet.haslayer(Ether):
        details.append(f"Source MAC: {packet[Ether].src}")
        details.append(f"Destination MAC: {packet[Ether].dst}")

    if packet.haslayer(IP):
        details.append(f"Source IP: {packet[IP].src}")
        details.append(f"Destination IP: {packet[IP].dst}")

    if packet.haslayer(TCP):
        details.append(f"Source Port: {packet[TCP].sport}")
        details.append(f"Destination Port: {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        details.append(f"Source Port: {packet[UDP].sport}")
        details.append(f"Destination Port: {packet[UDP].dport}")
    elif packet.haslayer(ICMP):
        details.append("ICMP Packet")

    try:
        payload = raw(packet).decode(errors="ignore")
        details.append(f"Payload (raw):\n{payload[:300]}")
    except:
        details.append("Payload: [Binary/Not Decodable]")

    detail_win = tk.Toplevel(root)
    detail_win.title("Packet Details")
    detail_win.geometry("500x400")

    text_box = tk.Text(detail_win, wrap="word")
    text_box.pack(fill="both", expand=True)
    text_box.insert("1.0", "\n".join(details))
    text_box.config(state="disabled")

# ---------------- Start Sniffing ----------------
def start_sniffing(iface="Wi-Fi", promisc=True):
    global sniffing, protocol_filter
    sniffing = True
    selected = filter_var.get()

    if selected == "All":
        protocol_filter = "ip"
    elif selected == "TCP":
        protocol_filter = "tcp"
    elif selected == "UDP":
        protocol_filter = "udp"
    elif selected == "ICMP":
        protocol_filter = "icmp"

    threading.Thread(
        target=lambda: sniff(
            filter=protocol_filter,
            prn=process_packet,
            store=False,
            stop_filter=lambda p: not sniffing
        ),
        daemon=True
    ).start()
    status_label.config(text=f"🔴 Sniffing Running... ({selected})")

# ---------------- Stop Sniffing ----------------
def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="🟢 Sniffing Stopped.")

# ---------------- Save Packets ----------------
def save_packets():
    if captured_packets:
        wrpcap("captured_packets.pcap", captured_packets)
        messagebox.showinfo("Saved", "✅ Packets saved in 'captured_packets.pcap'")
    else:
        messagebox.showwarning("No Packets", "⚠️ No packets captured yet.")

# ---------------- Update Graph ----------------
def update_graph():
    ax.clear()
    ax.plot(range(len(packet_rate)), packet_rate, marker="o")
    ax.set_title("Live Packet Rate")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Packets Captured")
    canvas.draw()

# ---------------- Search Packets by IP ----------------
def search_ip_packets():
    search_ip = search_entry.get().strip()
    packet_list.delete(0, tk.END)
    for packet in captured_packets:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if search_ip == "" or search_ip == src_ip or search_ip == dst_ip:
                proto = detect_protocol(packet)
                src_port = packet.sport if hasattr(packet, "sport") else "-"
                dst_port = packet.dport if hasattr(packet, "dport") else "-"
                mac_src = packet[Ether].src if packet.haslayer(Ether) else "N/A"
                mac_dst = packet[Ether].dst if packet.haslayer(Ether) else "N/A"
                packet_list.insert(
                    tk.END,
                    f"[{proto}] {packet.summary()} (Src Port: {src_port}, Dst Port: {dst_port}, Src MAC: {mac_src}, Dst MAC: {mac_dst})"
                )

# ---------------- Block/Unblock Selected IP ----------------
def block_selected_ip():
    selected = ip_tree.selection()
    if not selected:
        messagebox.showwarning("No Selection", "⚠️ Please select an IP to block.")
        return
    ip = ip_tree.item(selected[0])["values"][0]
    block_ip(ip)
    update_table()

def unblock_selected_ip():
    selected = ip_tree.selection()
    if not selected:
        messagebox.showwarning("No Selection", "⚠️ Please select an IP to unblock.")
        return
    ip = ip_tree.item(selected[0])["values"][0]
    unblock_ip(ip)
    update_table()

# ---------------- GUI Setup ----------------
root = tk.Tk()
root.title("Network Packet Sniffer BLOCK AUTOMATION")
root.geometry("1100x750")

# Buttons & Filter
frame = tk.Frame(root)
frame.pack(pady=10)

start_btn = tk.Button(frame, text="▶ Start", command=start_sniffing, bg="green", fg="white", width=10)
start_btn.grid(row=0, column=0, padx=5)

stop_btn = tk.Button(frame, text="⏹ Stop", command=stop_sniffing, bg="red", fg="white", width=10)
stop_btn.grid(row=0, column=1, padx=5)

save_btn = tk.Button(frame, text="💾 Save Packets", command=save_packets, bg="blue", fg="white", width=15)
save_btn.grid(row=0, column=2, padx=5)

# Protocol Filter
filter_var = tk.StringVar(value="All")
filter_label = tk.Label(frame, text="Filter:")
filter_label.grid(row=0, column=3, padx=5)
filter_menu = ttk.Combobox(frame, textvariable=filter_var, values=["All", "TCP", "UDP", "ICMP"], width=10, state="readonly")
filter_menu.grid(row=0, column=4, padx=5)

# Search IP
search_label = tk.Label(frame, text="Search IP:")
search_label.grid(row=1, column=0, padx=5, pady=5)
search_entry = tk.Entry(frame, width=15)
search_entry.grid(row=1, column=1, padx=5, pady=5)
search_btn = tk.Button(frame, text="🔎 Search IP", command=search_ip_packets, bg="orange", fg="white", width=12)
search_btn.grid(row=1, column=2, padx=5, pady=5)

# Block/Unblock Buttons
block_btn = tk.Button(frame, text="🛑 Block IP", command=block_selected_ip, bg="darkred", fg="white", width=12)
block_btn.grid(row=1, column=3, padx=5, pady=5)

unblock_btn = tk.Button(frame, text="✅ Unblock IP", command=unblock_selected_ip, bg="green", fg="white", width=12)
unblock_btn.grid(row=1, column=4, padx=5, pady=5)

# Status label
status_label = tk.Label(root, text="🟢 Ready.", font=("Arial", 12))
status_label.pack(pady=5)

# Split frame for IPs + Packets
split_frame = tk.Frame(root)
split_frame.pack(fill="both", expand=True, padx=10, pady=10)

# IP Table
ip_frame = tk.LabelFrame(split_frame, text="Active IPs & MACs")
ip_frame.pack(side="left", fill="both", expand=True, padx=5)
ip_columns = ("IP Address", "MAC Address", "Packets")
ip_tree = ttk.Treeview(ip_frame, columns=ip_columns, show="headings", height=20)
ip_tree.heading("IP Address", text="IP Address")
ip_tree.heading("MAC Address", text="MAC Address")
ip_tree.heading("Packets", text="Packets")
ip_tree.pack(fill="both", expand=True)

# Packet List
packet_frame = tk.LabelFrame(split_frame, text="Captured Packets")
packet_frame.pack(side="left", fill="both", expand=True, padx=5)
packet_list = tk.Listbox(packet_frame, width=120, height=20)
packet_list.pack(fill="both", expand=True)
packet_list.bind("<Double-1>", show_packet_details)

# Traffic Graph
graph_frame = tk.LabelFrame(root, text="Traffic Graph")
graph_frame.pack(fill="both", expand=True, padx=10, pady=10)
fig, ax = plt.subplots(figsize=(6,3))
canvas = FigureCanvasTkAgg(fig, master=graph_frame)
canvas.get_tk_widget().pack(fill="both", expand=True)

# ---------------- Start GUI ----------------
root.mainloop()



