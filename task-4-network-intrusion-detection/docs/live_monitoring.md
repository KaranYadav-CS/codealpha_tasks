# Live Network Monitoring Guide & Interface Operational Protocol
**CodeAlpha Cyber Security Internship — Task 4: Network Intrusion Detection System**

---

## 1. Overview & Operational Scope

While offline PCAP analysis operates deterministically against captured packet files, **Live Network Monitoring** configures Suricata to inspect raw packets passing through a physical or virtual network interface card (NIC) in real time.

> [!IMPORTANT]
> **Safety & Authorization Policy:**
> Live packet capturing inspects unencrypted packets across a local network segment. Never initiate live promiscuous capture on networks you do not own or lack explicit written authorization to monitor. Under CodeAlpha internship safety rules, automated live packet sniffing is disabled by default until explicit operator confirmation and kernel packet capture drivers are verified.

---

## 2. Prerequisites & Driver Dependencies

On Windows operating systems, user-mode applications cannot directly access physical Ethernet or Wi-Fi frames without a kernel-level packet filtering and NDIS driver.

| Component | Status on Present Host | Purpose & Requirement |
| :--- | :--- | :--- |
| **Operating System** | Windows 11 (64-bit AMD64) | Host OS platform |
| **Suricata Engine** | Installed (Version 7.0.10 RELEASE) | Real inspection and rule evaluation engine |
| **Kernel Packet Driver (Npcap)** | **Not Installed / Pending Operator Action** | Required for live packet capture from physical NICs |
| **User Privileges** | Standard User | Administrative elevation required for Npcap driver attachment |

### Installing Npcap for Live Capture
To enable live interface sniffing on Windows:
1. Download the official signed Npcap installer from [https://npcap.com/#download](https://npcap.com/#download) (e.g. `npcap-1.80.exe`).
2. Run the installer with administrative privileges.
3. During setup, check **"Install Npcap in WinPcap API-compatible Mode"** (ensures `wpcap.dll` and `Packet.dll` are registered in `C:\Windows\System32\Npcap`).
4. Complete installation and restart PowerShell.

---

## 3. Identifying the Target Network Interface

To configure live monitoring, you must determine the system's active network adapter GUID or interface index.

### Method A: Using Suricata Native Device Discovery
Run Suricata with the device listing flag:
```powershell
suricata.exe --list-runmodes
```
Or query device names:
```powershell
suricata.exe --pcap
```

### Method B: Using PowerShell
List all active IPv4 interfaces and their friendly names:
```powershell
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed
```
To obtain the Interface GUID (required by WinPcap / Npcap syntax):
```powershell
Get-NetAdapter | Select-Object Name, InterfaceGuid, InterfaceDescription
```

Example output:
```
Name      InterfaceGuid                          InterfaceDescription
----      -------------                          --------------------
Wi-Fi     {A1B2C3D4-E5F6-7890-ABCD-EF1234567890} Intel(R) Wi-Fi 6 AX201 160MHz
Ethernet  {F9E8D7C6-B5A4-3210-FEDC-BA0987654321} Realtek Gaming GbE Family Controller
```

---

## 4. Live Monitoring Execution Command

Once Npcap is installed and an administrative terminal is opened:

### Command Syntax (Windows Npcap):
```powershell
# Navigate to the project directory
cd "c:\Desktop\code alpha\task-4-network-intrusion-detection"

# Start Suricata live inspection on the selected interface GUID
suricata.exe -c config\suricata.yaml -i "\Device\NPF_{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}" -l logs
```

Alternatively, if listening on an adapter by IP address:
```powershell
suricata.exe -c config\suricata.yaml -i 192.168.1.150 -l logs
```

### How to Stop Live Monitoring
* Press `Ctrl + C` in the running PowerShell console.
* Suricata will gracefully flush active flow tables, close open log handles (`eve.json`, `fast.log`), and print aggregate capture statistics (packets received, dropped by kernel, invalid checksums).

---

## 5. Log Storage & Real-Time Alert Verification

When live monitoring is active, Suricata writes alerts into the designated `logs/` directory:

1. **`logs/fast.log`**: Single-line human-readable alert log.
   Follow alerts in real time via PowerShell:
   ```powershell
   Get-Content "logs\fast.log" -Wait -Tail 10
   ```
2. **`logs/eve.json`**: Comprehensive JSON stream containing full metadata, flow statistics, protocols, and payload snippets.
3. **`dashboard/server.py`**: The local web console automatically reads newly appended alerts when refreshed.

---

## 6. Distinguishing Offline PCAP Mode from Live Monitoring

| Attribute | Offline PCAP Analysis (Tested & Verified) | Live Network Monitoring (Documented Procedure) |
| :--- | :--- | :--- |
| **Execution Command** | `suricata -c config/suricata.yaml -r data/lab_traffic.pcap -l logs` | `suricata -c config/suricata.yaml -i <Interface> -l logs` |
| **Input Source** | Synthetic lab PCAP file (`data/lab_traffic.pcap`) | Live physical or virtual NIC packet stream |
| **Driver Required** | None (Runs user-mode file parser) | Npcap NDIS kernel-mode driver required |
| **Privileges Needed** | Standard user permissions | Administrator elevation for raw socket binding |
| **Reproducibility** | 100% deterministic (exact same packet timing) | Dependent on dynamic real-world network traffic |
| **Current Project Status** | **VERIFIED & OPERATIONAL** (All 7 rules tested) | **DOCUMENTED & READY** (Awaiting operator approval & Npcap) |
