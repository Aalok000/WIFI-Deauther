# 🛠️ WiFi Deauther with 2.4GHz & 5GHz Support

A Python-based WiFi deauthentication tool that scans nearby wireless access points (APs) and prepares for deauthentication attacks. Built for flexibility, it supports both **2.4GHz** and **5GHz** bands (depending on your wireless adapter capabilities).

> ⚠️ **Use only on networks you own or have explicit permission to test. Unauthorized use is illegal.**

---

## 🚀 Features

- 🔍 Passive scanning for wireless access points  
- 📡 2.4GHz & 5GHz band support (hardware-dependent)  
- 🎛️ Manual or auto-selection of target SSID/BSSID  
- 🧠 Channel-based targeting  
- ⚙️ Automatic monitor mode setup  
- 📊 Terminal-based interface with debug logging  
- 🚦 Graceful shutdown on Ctrl+C  
- 💻 Built with Scapy + native Linux WiFi tools  

---

## 📋 Requirements

- 🐧 Linux OS (Kali Linux recommended)  
- 🐍 Python 3.6+  
- ✅ Wireless adapter that supports:
  - Monitor mode
  - Packet injection
  - (Optional) 5GHz band

---

## 📦 Installation

### 1. Install required tools & drivers

```bash
sudo apt update
sudo apt install python3 python3-pip aircrack-ng iw net-tools -y
