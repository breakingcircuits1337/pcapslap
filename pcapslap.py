#!/usr/bin/env python3
from scapy.all import PcapReader
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import TCP, UDP
from scapy.layers.dns import DNSQR
import re
import base64
import argparse
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init()

class PCAPAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.patterns = {
            # Existing patterns...
            'thm_flag': re.compile(r'THM\{[^}]+\}', re.I),
            'htb_flag': re.compile(r'HTB\{[^}]+\}', re.I),
            'generic_flag': re.compile(r'flag\{[^}]+\}', re.I),
            'base64_flag': re.compile(r'([A-Za-z0-9+/]{20,}={0,2})', re.I),
            'hex_flag': re.compile(r'(?:0x)?[0-9a-fA-F]{8,}', re.I),
            'md5_hash': re.compile(r'[a-fA-F0-9]{32}', re.I),
            'sha1_hash': re.compile(r'[a-fA-F0-9]{40}', re.I),
        }
        self.protocol_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL'
        }

    def display_banner(self):
        banner = r"""
        ____  ____  ___    ___    _   __ ______   ______   ______   ___    ____  ____ 
       / __ )/ __ \/   |  /   |  / | / // ____/  / ____/  / ____/  /   |  / __ \/ __ \
      / __  / /_/ / /| | / /| | /  |/ // / __   / __/    / /_     / /| | / /_/ / / / /
     / /_/ / _, _/ ___ |/ ___ |/ /|  // /_/ /  / /___   / __/    / ___ |/ ____/ /_/ / 
    /_____/_/ |_/_/  |_/_/  |_/_/ |_/ \____/  /_____/  /_/      /_/  |_/_/   /_____/  
        """
        print(Fore.GREEN + banner + Style.RESET_ALL)
        print(Fore.GREEN + "Welcome to Breaking Circuits PCAP Slap!" + Style.RESET_ALL)
        print(Fore.GREEN + "=======================================" + Style.RESET_ALL)
        print(Fore.GREEN + "Commands:" + Style.RESET_ALL)
        print(Fore.GREEN + "1. Analyze PCAP file: ./enhanced_pcap_analyzer.py <pcap_file>" + Style.RESET_ALL)
        print(Fore.GREEN + "2. Save output to file: ./enhanced_pcap_analyzer.py <pcap_file> -o output.txt" + Style.RESET_ALL)
        print(Fore.GREEN + "3. Enable verbose mode: ./enhanced_pcap_analyzer.py <pcap_file> -v" + Style.RESET_ALL)
        print(Fore.GREEN + "4. Use custom patterns: ./enhanced_pcap_analyzer.py <pcap_file> -p patterns.txt" + Style.RESET_ALL)
        print(Fore.GREEN + "=======================================\n" + Style.RESET_ALL)

    def decode_base64(self, data):
        try:
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            if any(c.isprintable() for c in decoded):
                return decoded
            return None
        except:
            return None

    def decode_hex(self, data):
        try:
            decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
            if any(c.isprintable() for c in decoded):
                return decoded
            return None
        except:
            return None

    def extract_files(self, packet):
        if packet.haslayer('Raw'):
            raw_data = packet['Raw'].load
            if raw_data.startswith(b'\x89PNG'):
                with open('extracted_image.png', 'wb') as f:
                    f.write(raw_data)
                return 'PNG file extracted'
            elif raw_data.startswith(b'%PDF'):
                with open('extracted_document.pdf', 'wb') as f:
                    f.write(raw_data)
                return 'PDF file extracted'
            elif raw_data.startswith(b'<?xml') or raw_data.startswith(b'<html'):
                with open('extracted_file.html', 'wb') as f:
                    f.write(raw_data)
                return 'HTML/XML file extracted'
        return None

    def analyze_dns(self, packet):
        if packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            findings = []
            if 'flag' in dns_query.lower():
                findings.append(('DNS Query', dns_query))
            return findings
        return None

    def analyze_ftp(self, packet):
        if packet.haslayer('Raw'):
            raw_data = packet['Raw'].load.decode('utf-8', errors='ignore')
            if 'USER' in raw_data or 'PASS' in raw_data:
                return [('FTP Credentials', raw_data.strip())]
        return None

    def analyze_smtp(self, packet):
        if packet.haslayer('Raw'):
            raw_data = packet['Raw'].load.decode('utf-8', errors='ignore')
            if 'AUTH LOGIN' in raw_data or 'MAIL FROM' in raw_data:
                return [('SMTP Data', raw_data.strip())]
        return None

    def analyze_hex(self, packet):
        if packet.haslayer('Raw'):
            raw_data = packet['Raw'].load.hex()
            decoded = self.decode_hex(raw_data)
            if decoded:
                return [('Hex Decoded', decoded)]
        return None

    def analyze_packet(self, packet):
        findings = []
        if self.verbose:
            print(f"Analyzing packet: {packet.summary()}")

        try:
            if packet.haslayer('Raw'):
                raw_data = packet['Raw'].load
                str_data = raw_data.decode('utf-8', errors='ignore')

                for pattern_name, pattern in self.patterns.items():
                    matches = pattern.findall(str_data)
                    for match in matches:
                        if pattern_name == 'base64':
                            decoded = self.decode_base64(match)
                            if decoded:
                                findings.append(('Decoded Base64', decoded))
                        else:
                            findings.append((pattern_name.title(), match))

                file_extraction_result = self.extract_files(packet)
                if file_extraction_result:
                    findings.append(('File Extraction', file_extraction_result))

            dns_findings = self.analyze_dns(packet)
            if dns_findings:
                findings.extend(dns_findings)

            ftp_findings = self.analyze_ftp(packet)
            if ftp_findings:
                findings.extend(ftp_findings)

            smtp_findings = self.analyze_smtp(packet)
            if smtp_findings:
                findings.extend(smtp_findings)

            hex_findings = self.analyze_hex(packet)
            if hex_findings:
                findings.extend(hex_findings)

        except Exception as e:
            print(f"Error analyzing packet: {str(e)}", file=sys.stderr)

        return findings

def analyze_pcap(pcap_file, output_file=None, verbose=False):
    analyzer = PCAPAnalyzer(verbose)
    analyzer.display_banner()
    findings = []
    packet_count = 0

    print(Fore.GREEN + f"Starting analysis of {pcap_file}" + Style.RESET_ALL)

    try:
        with PcapReader(pcap_file) as pcap_reader:
            for packet in pcap_reader:
                packet_count += 1
                if packet_count % 1000 == 0:
                    print(Fore.GREEN + f"Processed {packet_count} packets..." + Style.RESET_ALL)

                packet_findings = analyzer.analyze_packet(packet)
                if packet_findings:
                    timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
                    findings.append((timestamp, packet_findings))

    except Exception as e:
        print(Fore.RED + f"Error reading PCAP: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
        return

    grouped_findings = {}
    for timestamp, packet_findings in findings:
        for finding_type, value in packet_findings:
            if finding_type not in grouped_findings:
                grouped_findings[finding_type] = []
            grouped_findings[finding_type].append((timestamp, value))

    output = [
        "PCAP Analysis Results",
        "====================",
        f"Total Packets: {packet_count}\n"
    ]

    for finding_type, items in sorted(grouped_findings.items()):
        output.append(f"\n{finding_type}:")
        output.append("=" * len(finding_type))
        for timestamp, value in items:
            output.append(f"[{timestamp}] {value}")

    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(output))
        print(Fore.GREEN + f"\nResults written to {output_file}" + Style.RESET_ALL)
    else:
        print('\n'.join(output))

def main():
    try:
        parser = argparse.ArgumentParser(description='Enhanced PCAP Credential Analyzer')
        parser.add_argument('pcap_file', help='Path to the PCAP file')
        parser.add_argument('-o', '--output', help='Output file (optional)')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
        args = parser.parse_args()
        analyze_pcap(args.pcap_file, args.output, args.verbose)
    except Exception as e:
        print(Fore.RED + f"Error: {str(e)}" + Style.RESET_ALL, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()