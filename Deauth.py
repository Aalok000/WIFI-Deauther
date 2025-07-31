#!/usr/bin/env python3

import os
import sys
import signal
import logging
import argparse
import threading
from typing import Dict, Generator, List, Union, Set
from collections import defaultdict
from scapy.layers.dot11 import RadioTap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11Deauth, Dot11
from scapy.all import *
from time import sleep, time
from threading import Thread

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Constants and UI Elements
DELIM = "=" * 80
BOLD = "\033[1m"
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BD_MACADDR = "ff:ff:ff:ff:ff:ff"

class BandType:
    T_24GHZ = "2.4GHz"
    T_50GHZ = "5GHz"

class SSID:
    def __init__(self, name, mac_addr, band_type):
        self.name = name
        self.mac_addr = mac_addr
        self.band_type = band_type
        self.channel = None
        self.clients = []

    def add_channel(self, channel):
        self.channel = channel

def print_info(msg, end="\n"):
    print(f"[*] {msg}", end=end)

def print_error(msg):
    print(f"{RED}[!] {msg}{RESET}")

def print_cmd(msg):
    print(f"{YELLOW}[>] {msg}{RESET}")

def print_warning(msg):
    print(f"{YELLOW}[!] {msg}{RESET}")

def print_debug(msg):
    print(f"[DEBUG] {msg}")

def print_input(prompt):
    return input(f"{BOLD}[?] {prompt}{RESET} ")

def printf(msg, end="\n"):
    print(msg, end=end)

def clear_line(lines=1):
    for _ in range(lines):
        sys.stdout.write("\033[F")  # Move cursor up one line
        sys.stdout.write("\033[K")  # Clear line

def get_time():
    return int(time())

def frequency_to_channel(freq):
    if 2412 <= freq <= 2484:
        return (freq - 2412) // 5 + 1
    elif freq == 2484:
        return 14
    elif 5170 <= freq <= 5825:
        return (freq - 5170) // 5 + 34
    return None

def channel_to_frequency(channel):
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    elif channel == 14:
        return 2484
    elif 36 <= channel <= 165:
        return 5000 + channel * 5
    return None

class Interceptor:
    _ABORT = False
    _PRINT_STATS_INTV = 1
    _DEAUTH_INTV = 0.100
    _CH_SNIFF_TO = 2
    _SSID_STR_PAD = 42

    def __init__(self, net_iface, skip_monitor_mode_setup, kill_networkmanager,
                 ssid_name, bssid_addr, custom_client_macs, custom_channels, 
                 deauth_all_channels, autostart, debug_mode, band):
        self.interface = net_iface
        self.band = band.lower() if band else None
        self._max_consecutive_failed_send_lim = 5 / Interceptor._DEAUTH_INTV
        self._current_channel_num = None
        self._current_channel_aps = set()
        self.attack_loop_count = 0
        self.target_ssid = None
        self._debug_mode = debug_mode

        if not skip_monitor_mode_setup:
            print_info(f"Setting up monitor mode...")
            if not self._enable_monitor_mode():
                print_error(f"Monitor mode was not enabled properly")
                raise Exception("Unable to turn on monitor mode")
            print_info(f"Monitor mode was set up successfully")
        else:
            print_info(f"Skipping monitor mode setup...")

        if kill_networkmanager:
            print_info(f"Killing NetworkManager...")
            if not self._kill_networkmanager():
                print_error(f"Failed to kill NetworkManager...")

        self._channel_range = self._get_supported_channels()
        print_debug(f"Supported channels: {[c for c in self._channel_range.keys()]}")
        self._all_ssids = {band: dict() for band in [BandType.T_24GHZ, BandType.T_50GHZ]}
        self._custom_ssid_name = ssid_name
        self._custom_bssid_addr = bssid_addr
        self._custom_target_client_mac = custom_client_macs.split(',') if custom_client_macs else []
        self._custom_target_ap_channels = [int(ch) for ch in custom_channels.split(',')] if custom_channels else []
        self._custom_target_ap_last_ch = 0
        self._midrun_output_buffer = []
        self._midrun_output_lck = threading.RLock()
        self._deauth_all_channels = deauth_all_channels
        self._ch_iterator = self._init_channels_generator() if self._deauth_all_channels else None
        print_info(f"De-auth all channels enabled -> {BOLD}{self._deauth_all_channels}{RESET}")
        self._autostart = autostart

    def _enable_monitor_mode(self):
        cmds = [
            f"sudo ip link set {self.interface} down",
            f"sudo iw {self.interface} set monitor control",
            f"sudo ip link set {self.interface} up"
        ]
        for cmd in cmds:
            print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
            if os.system(cmd):
                os.system(f"sudo ip link set {self.interface} up")
                return False
        sleep(2)
        return True

    def _kill_networkmanager(self):
        cmd = 'systemctl stop NetworkManager'
        print_cmd(f"Running command -> '{BOLD}{cmd}{RESET}'")
        return os.system(cmd) == 0

    def _get_supported_channels(self):
        channels = {}
        output = os.popen(f'iwlist {self.interface} frequency').read()
        for line in output.split('\n'):
            if 'Channel' in line and 'Current' not in line:
                try:
                    ch = int(line.split('Channel ')[1].split(':')[0].strip())
                    freq = float(line.split('Frequency:')[1].split(' ')[1])
                    if self.band == '2.4ghz' and freq < 3000:
                        channels[ch] = defaultdict(dict)
                    elif self.band == '5ghz' and freq > 3000:
                        channels[ch] = defaultdict(dict)
                    elif not self.band:
                        channels[ch] = defaultdict(dict)
                except:
                    continue
        return channels

    @staticmethod
    def user_abort(signum, frame):
        Interceptor._ABORT = True
        print_error(f"User requested shutdown (signal {signum})")
        sys.exit(0)

    def _set_channel(self, ch_num):
        freq = channel_to_frequency(ch_num)
        cmd = f"iw dev {self.interface} set channel {ch_num}"
        print_debug(f"Setting channel {ch_num} ({freq} MHz)")
        os.system(cmd)
        self._current_channel_num = ch_num
        sleep(0.1)

    def _init_channels_generator(self):
        ch_range = list(self._channel_range.keys())
        ctr = 0
        while not Interceptor._ABORT:
            yield ch_range[ctr]
            ctr = (ctr + 1) % len(ch_range)

    def _scan_channels_for_aps(self):
        print_info("Scanning for access points...")

        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                ssid = pkt[Dot11Elt].info.decode(errors="ignore")
                bssid = pkt[Dot11].addr2
                try:
                    freq = pkt[RadioTap].ChannelFrequency
                    ch = frequency_to_channel(freq)
                except:
                    ch = None
                if ch is None:
                    return
                band_type = BandType.T_24GHZ if ch <= 14 else BandType.T_50GHZ
                if ssid not in self._all_ssids[band_type]:
                    ap = SSID(ssid, bssid, band_type)
                    ap.add_channel(ch)
                    self._all_ssids[band_type][ssid] = ap

        for ch in sorted(self._channel_range.keys()):
            if Interceptor._ABORT:
                break
            self._set_channel(ch)
            sniff(iface=self.interface, prn=packet_handler, timeout=self._CH_SNIFF_TO, store=0)

    def run(self):
        if self.band == '5ghz' and not any(ch > 14 for ch in self._channel_range.keys()):
            print_error("No 5GHz channels detected - check your adapter and regulatory domain")
            print_info("Try: sudo iw reg set US && sudo ip link set {self.interface} down && sudo ip link set {self.interface} up")
            return

        self.target_ssid = self._start_initial_ap_scan()
        if not self.target_ssid:
            print_error("No target SSID selected")
            return

        ssid_ch = self.target_ssid.channel
        if ssid_ch > 14:
            print_info("5GHz target detected - using appropriate channel settings")

        print_info(f"Attacking target {self.target_ssid.name}")
        print_info(f"Setting channel -> {ssid_ch}")
        self._set_channel(ssid_ch)
        printf(f"{DELIM}\n")

        threads = []
        for action in [self._run_deauther, self._listen_for_clients, self.report_status]:
            t = Thread(target=action)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def _start_initial_ap_scan(self):
        self._scan_channels_for_aps()
        for band_ssids in self._all_ssids.values():
            for ssid_name, ssid_obj in band_ssids.items():
                self._channel_range[ssid_obj.channel][ssid_name] = ssid_obj

        printf(f"{DELIM}\n")
        printf(f"[   ] {'SSID Name'.ljust(Interceptor._SSID_STR_PAD - 6)}Channel{'MAC Address'.rjust(20)}")

        ctr = 0
        target_map = {}
        for channel, all_channel_aps in sorted(self._channel_range.items()):
            for ssid_name, ssid_obj in all_channel_aps.items():
                ctr += 1
                target_map[ctr] = ssid_obj
                printf(f"[{BOLD}{YELLOW}{str(ctr).rjust(3)}{RESET}] "
                      f"{ssid_obj.name.ljust(Interceptor._SSID_STR_PAD - 6)}"
                      f"{str(ssid_obj.channel).ljust(7)}"
                      f"{ssid_obj.mac_addr}")

        if not target_map:
            print_error("No APs were found, quitting...")
            return None

        printf(DELIM)

        if self._autostart and len(target_map) == 1:
            print_info("One target found, autostarting...")
            return target_map[1]

        while True:
            try:
                chosen = int(print_input(f"Choose target (1-{ctr}):"))
                if chosen in target_map:
                    return target_map[chosen]
                print_error("Invalid selection")
            except ValueError:
                print_error("Please enter a number")

    def _run_deauther(self):
        print_info("Deauth function stub - you can implement packet sending here.")

    def _listen_for_clients(self):
        print_info("Client listener stub - implement client sniffing if needed.")

    def report_status(self):
        while not Interceptor._ABORT:
            print_info("Monitoring... (press Ctrl+C to stop)")
            sleep(5)

def main():
    parser = argparse.ArgumentParser(description='WiFi Deauther with 5GHz support')
    parser.add_argument('-i', '--iface', required=True, help='Network interface')
    parser.add_argument('--skip-monitormode', action='store_true', help='Skip monitor mode setup')
    parser.add_argument('-k', '--kill', action='store_true', help='Kill NetworkManager')
    parser.add_argument('-s', '--ssid', help='Target SSID name')
    parser.add_argument('-b', '--bssid', help='Target BSSID address')
    parser.add_argument('--clients', help='Target client MACs (comma separated)')
    parser.add_argument('-c', '--channels', help='Custom channels (comma separated)')
    parser.add_argument('-a', '--autostart', action='store_true', help='Autostart if single AP found')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--deauth-all-channels', action='store_true', help='Deauth on all channels')
    parser.add_argument('--band', choices=['2.4ghz', '5ghz'], help='Force band selection')

    signal.signal(signal.SIGINT, Interceptor.user_abort)

    printf(f"\n{'='*80}\n")
    printf(f"Make sure of the following:")
    printf(f"1. You are running as {BOLD}root{RESET}")
    printf(f"2. Your wireless adapter supports {BOLD}monitor mode{RESET}")
    printf(f"3. For 5GHz: Set proper regulatory domain (sudo iw reg set US)")
    printf(f"\nWritten by {BOLD}@Aalok000{RESET}")
    printf(f"{'='*80}")

    if "linux" not in sys.platform:
        raise OSError("Unsupported operating system, only Linux is supported")
    elif os.geteuid() != 0:
        raise PermissionError("Must be run as root")

    pargs = parser.parse_args()
    attacker = Interceptor(
        net_iface=pargs.iface,
        skip_monitor_mode_setup=pargs.skip_monitormode,
        kill_networkmanager=pargs.kill,
        ssid_name=pargs.ssid,
        bssid_addr=pargs.bssid,
        custom_client_macs=pargs.clients,
        custom_channels=pargs.channels,
        deauth_all_channels=pargs.deauth_all_channels,
        autostart=pargs.autostart,
        debug_mode=pargs.debug,
        band=pargs.band
    )
    attacker.run()

if __name__ == "__main__":
    main()
