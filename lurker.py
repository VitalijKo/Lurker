import requests
import sqlite3
import os
import argparse
from scapy.all import *
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.inet import IP
from scapy.sendrecv import sniff
from datetime import datetime, timedelta
from colorama import Fore, Style, init

init()

dns_requests = {}
dns_types = {}


class DNSDataStorage:
    def __init__(self, db_file='dnsdata.db'):
        self.db_file = db_file
        self.connection = self.create_connection()

        if self.connection:
            self.create_table()

    def create_connection(self):
        try:
            return sqlite3.connect(self.db_file)
        except sqlite3.Error as e:
            print('Failed to connect to the database:', e)

            return

    def create_table(self):
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dns_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_mac TEXT,
                    destination_mac TEXT,
                    packet_size INTEGER,
                    ttl TEXT,
                    ip_checksum INTEGER,
                    udp_checksum INTEGER,
                    domain TEXT,
                    dns_type INTEGER
                )
            ''')

            self.connection.commit()
        except sqlite3.Error as e:
            print('Database error:', e)

    def insert_dns_request(
        self,
        timestamp,
        source_ip,
        destination_ip,
        source_mac,
        destination_mac,
        packet_size,
        ttl,
        ip_checksum,
        udp_checksum,
        domain,
        dns_type
    ):
        if not self.connection:
            print('No database connection')

            return

        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO dns_requests (timestamp, source_ip, destination_ip, source_mac, destination_mac, packet_size, ttl, ip_checksum, udp_checksum, domain, dns_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                source_ip,
                destination_ip,
                source_mac,
                destination_mac,
                packet_size,
                ttl,
                ip_checksum,
                udp_checksum,
                domain,
                dns_type
            ))

            self.connection.commit()
        except sqlite3.Error as e:
            print('Database error:', e)

    def retrieve_dns_requests(self):
        if not self.connection:
            print('No database connection')

            return []

        try:
            cursor = self.connection.cursor()

            cursor.execute('SELECT * FROM dns_requests')

            return cursor.fetchall()
        except sqlite3.Error as e:
            print('Database error:', e)

            return []

    def close(self):
        if self.connection:
            self.connection.close()


def resolve_dns_doh(dns_request):
    url = f'https://cloudflare-dns.com/dns-query?name={dns_request}&type=A'

    headers = {
        'Accept': 'application/dns-json'
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        try:
            result = response.json()

            if 'Answer' in result:
                answers = result['Answer']

                return [answer['data'] for answer in answers]
        except Exception as e:
            print(f'{Style.BRIGHT}{Fore.RED}[!] Error resolving DNS over HTTPS: {e}{Style.RESET_ALL}')

    return


def dns_sniffer(
    pkt,
    output_file,
    target_ip=None,
    use_doh=False,
    filter_domains=[],
    dns_storage=None):

    if target_ip and pkt[IP].src != target_ip and pkt[IP].dst != target_ip:
        return

    dns_storage = DNSDataStorage()

    if pkt.haslayer(DNSQR) and pkt.haslayer(Ether):
        ip_header = pkt.getlayer('IP')
        udp_header = pkt.getlayer('UDP')
        dns_request = pkt[DNSQR].qname.decode()
        dns_type = pkt[DNSQR].qtype
        dns_src_ip = pkt[IP].src
        dns_dest_ip = pkt[IP].dst
        ether_header = pkt[Ether]
        src_mac = ether_header.src
        dst_mac = ether_header.dst
        ttl = ip_header.ttl if ip_header.ttl else 'N/A'
        ip_checksum = ip_header.chksum
        udp_checksum = udp_header.chksum

        timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')

        if filter_domains and not any(domain in dns_request for domain in filter_domains):
            return

        print(f'{Style.BRIGHT}{Fore.RED}\tDNS Request:{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}Timestamp      : {Fore.YELLOW}{timestamp}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}Source IP      : {Fore.GREEN}{dns_src_ip}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}Destination IP : {Fore.GREEN}{dns_dest_ip}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}Source MAC     : {Style.RESET_ALL}{src_mac}')
        print(f'{Style.BRIGHT}Destination MAC: {Style.RESET_ALL}{dst_mac}')
        print(f'{Style.BRIGHT}Packet Size    : {Fore.GREEN}{len(pkt)} bytes{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}TTL            : {Style.RESET_ALL}{ttl}')
        print(f'{Style.BRIGHT}Type           : {Fore.GREEN}{dns_type}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}IP Checksum    : {Fore.GREEN}{ip_checksum}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}UDP Checksum   : {Fore.GREEN}{udp_checksum}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}DNS Request    : {Fore.GREEN}{dns_request}{Style.RESET_ALL}')
        print('*' * 64)

        if use_doh:
            resolved_ips = resolve_dns_doh(dns_request)

            if resolved_ips:
                print(f'{Style.BRIGHT}{Fore.RED}\tDNS Request (DoH){Style.RESET_ALL}')
                print(f'{Style.BRIGHT}Timestamp      : {Fore.YELLOW}{timestamp}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}Source IP      : {Fore.RED}{dns_src_ip}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}Destination IP : {Fore.RED}{dns_dest_ip}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}Source MAC     : {Style.RESET_ALL}{src_mac}')
                print(f'{Style.BRIGHT}Destination MAC: {Style.RESET_ALL}{dst_mac}')
                print(f'{Style.BRIGHT}Packet Size    : {Fore.GREEN}{len(pkt)} bytes{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}TTL            : {Style.RESET_ALL} {ttl}')
                print(f'{Style.BRIGHT}Type           : {Fore.GREEN}{dns_type}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}IP Checksum    : {Fore.GREEN}{ip_checksum}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}UDP Checksum   : {Fore.GREEN}{udp_checksum}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}DNS Request    : {Fore.GREEN}{dns_request}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}Resolved IPs   : {Fore.GREEN}{", ".join(resolved_ips)}{Style.RESET_ALL}')
                print('*' * 64)

            else:
                print(f'{Style.BRIGHT}{Fore.RED}\tDNS Request (DoH){Style.RESET_ALL}')
                print(f'{Style.BRIGHT}Timestamp      : {Fore.YELLOW}{timestamp}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}Source IP      : {Fore.RED}{dns_src_ip}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}Destination IP : {Fore.RED}{dns_dest_ip}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}Source MAC     : {Style.RESET_ALL}{src_mac}')
                print(f'{Style.BRIGHT}Destination MAC: {Style.RESET_ALL}{dst_mac}')
                print(f'{Style.BRIGHT}Packet Size    : {len(pkt)} bytes{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}TTL            : {Style.RESET_ALL}{ttl}')
                print(f'{Style.BRIGHT}Type           : {dns_type}')
                print(f'{Style.BRIGHT}IP Checksum    : {Fore.GREEN}{ip_checksum}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}UDP Checksum   : {Fore.GREEN}{udp_checksum}{Style.RESET_ALL}')
                print(f'{Style.BRIGHT}DNS Request    : {dns_request}')
                print(f'{Style.BRIGHT}Resolved IPs   : (Cannot resolve with DoH)')
                print('*' * 64)

        else:
            print(f'{Style.BRIGHT}{Fore.RED}\tDNS Request{Style.RESET_ALL}')
            print(f'{Style.BRIGHT}Timestamp      : {Fore.YELLOW}{timestamp}{Style.RESET_ALL}')
            print(f'{Style.BRIGHT}Source IP      : {Fore.RED}{dns_src_ip}{Style.RESET_ALL}')
            print(f'{Style.BRIGHT}Destination IP : {Fore.RED}{dns_dest_ip}{Style.RESET_ALL}')
            print(f'{Style.BRIGHT}Source MAC     : {Style.RESET_ALL}{src_mac}')
            print(f'{Style.BRIGHT}Destination MAC: {Style.RESET_ALL}{dst_mac}')
            print(f'{Style.BRIGHT}Packet Size    : {Fore.GREEN}{len(pkt)} bytes{Style.RESET_ALL}')
            print(f'{Style.BRIGHT}TTL            : {Style.RESET_ALL}{ttl}')
            print(f'{Style.BRIGHT}Type           : {dns_type}')
            print(f'{Style.BRIGHT}IP Checksum    : {Fore.GREEN}{ip_checksum}{Style.RESET_ALL}')
            print(f'{Style.BRIGHT}UDP Checksum   : {Fore.GREEN}{udp_checksum}{Style.RESET_ALL}')
            print(f'{Style.BRIGHT}DNS Request    : {dns_request}')
            print('*' * 64)

        if dns_request in dns_requests:
            dns_requests[dns_request][0] += 1

        else:
            dns_requests[dns_request] = [1, []]

        if dns_type in dns_types:
            dns_types[dns_type] += 1

        else:
            dns_types[dns_type] = 1

        if output_file:
            with open(output_file, 'a') as file:
                file.write('\tDNS Request details:\n')
                file.write(f'Timestamp      : {timestamp}\n')
                file.write(f'Source IP      : {dns_src_ip}\n')
                file.write(f'Destination IP : {dns_dest_ip}\n')
                file.write(f'Destination IP : {dns_dest_ip}\n')
                file.write(f'Source mac     : {src_mac}\n')
                file.write(f'Packet Size    : {len(pkt)} bytes\n')
                file.write(f'Tll            : {ttl}\n')
                file.write(f'Type           : {dns_type}\n')
                file.write(f'IP Checksum    : {ip_checksum}\n')
                file.write(f'UDP Checksum   : {udp_checksum}\n')
                file.write(f'DNS Request    : {dns_request}\n')
                file.write(f'{"-" * 64}\n')

        dns_storage.insert_dns_request(
            timestamp,
            dns_src_ip,
            dns_dest_ip,
            src_mac,
            dst_mac,
            len(pkt),
            ttl,
            ip_checksum,
            udp_checksum,
            dns_request,
            dns_type
        )

    if pkt.haslayer(DNSRR):
        dns_response = pkt[DNSRR].rrname.decode()
        dns_type = pkt[DNSRR].type
        dns_src_ip = pkt[IP].src
        dns_dest_ip = pkt[IP].dst
        timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')

        if filter_domains and not any(domain in dns_response for domain in filter_domains):
            return

        print(f'{Style.BRIGHT}{Fore.RED}\tDNS Response details{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}Timestamp      : {Fore.YELLOW}{timestamp}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}Source IP      : {Fore.RED}{dns_src_ip}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}Destination IP : {Fore.RED}{dns_dest_ip}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}Source MAC     : {Style.RESET_ALL}{src_mac}')
        print(f'{Style.BRIGHT}Destination MAC: {Style.RESET_ALL}{dst_mac}')
        print(f'{Style.BRIGHT}Packet Size    : {Fore.GREEN}{len(pkt)} bytes{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}TTL            : {Style.RESET_ALL}{ttl}')
        print(f'{Style.BRIGHT}Type           : {dns_type}')
        print(f'{Style.BRIGHT}IP Checksum    : {Fore.GREEN}{ip_checksum}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}UDP Checksum   : {Fore.GREEN}{udp_checksum}{Style.RESET_ALL}')
        print(f'{Style.BRIGHT}DNS Response   : {dns_response}')
        print('*' * 64)

        if dns_response in dns_requests:
            dns_requests[dns_response][1].append(dns_src_ip)

        if dns_type in dns_types:
            dns_types[dns_type] += 1

        else:
            dns_types[dns_type] = 1

        if output_file:
            with open(output_file, 'a') as file:
                file.write(f'\tDNS Response details:\n')
                file.write(f'Timestamp      : {timestamp}\n')
                file.write(f'Source IP      : {dns_src_ip}\n')
                file.write(f'Destination IP : {dns_dest_ip}\n')
                file.write(f'Source mac     : {src_mac}\n')
                file.write(f'Destination Mac: {dst_mac}\n')
                file.write(f'Packet Size    : {len(pkt)} bytes\n')
                file.write(f'Tll            : {ttl}\n')
                file.write(f'Type           : {dns_type}\n')
                file.write(f'IP Checksum    : {ip_checksum}\n')
                file.write(f'UDP Checksum   : {udp_checksum}\n')
                file.write(f'DNS Response   : {dns_response}\n')
                file.write(f'{"-" * 64}\n')

            dns_storage.insert_dns_request(
                timestamp,
                dns_src_ip,
                dns_dest_ip,
                src_mac,
                dst_mac,
                len(pkt),
                ttl,
                ip_checksum,
                udp_checksum,
                dns_response,
                dns_type
            )

        dns_storage.close()


def dns_analyzer():
    if dns_requests:
        print('\nDNS Data Analysis:')

        total_requests = sum(count for count, _ in dns_requests.values())
        unique_domains = len(dns_requests)
        most_requested = max(dns_requests, key=lambda x: dns_requests[x][0])

        most_requested_count = dns_requests[most_requested][0]

        resolved_by_counts = {}

        for resolved_ips in dns_requests.values():
            for ip in resolved_ips[1]:
                if ip in resolved_by_counts:
                    resolved_by_counts[ip] += 1

                else:
                    resolved_by_counts[ip] = 1

        print(f'{Style.BRIGHT}Total DNS Requests: {total_requests}')
        print(f'{Style.BRIGHT}Unique Domains: {unique_domains}')
        print(f'{Style.BRIGHT}Most Requested Domain: {most_requested} (Count: {most_requested_count})')
        print('\nMost Resolved by:')

        for ip, count in resolved_by_counts.items():
            print(f'{Style.BRIGHT}{ip}: {count}')

        if dns_types:
            print('\nDNS Type Analysis:')

            for dns_type, count in dns_types.items():
                print(f'{Style.BRIGHT}Type: {dns_type} - Count: {count}')

    else:
        print('No DNS requests to analyze.')


parser = argparse.ArgumentParser(description='Lurker')
parser.add_argument('-i', '--interface', help='Specify the network interface, for example "eth0"', required=True)
parser.add_argument('-o', '--output', help='Specify the filename to save the results to a file')
parser.add_argument('-t', '--target-ip', help='Specify specific target IP address to monitor')
parser.add_argument('-fd', '--target-domains', nargs='+', help='Filter DNS requests by specified domains', default=[])
parser.add_argument('--doh', help='Enable DNS over HTTPS', action='store_true')
parser.add_argument('-d', '--database', help='Enable database storage', action='store_true')
args = parser.parse_args()

filter_rule = 'udp port 53'

try:
    print(f'{Style.BRIGHT}{Fore.MAGENTA}\t\tDNS Packet Sniffer started...{Style.RESET_ALL}')

    dns_storage = DNSDataStorage() if args.database else None

    sniff(
        iface=args.interface,
        filter=filter_rule,
        prn=lambda pkt: dns_sniffer(
            pkt,
            args.output,
            args.target_ip,
            args.doh,
            args.target_domains,
            dns_storage
        )
    )

    dns_analyzer()
except PermissionError:
    print(f'{Style.BRIGHT}{Fore.RED}Error: You dont have sufficient privileges{Style.RESET_ALL}')

    os.abort()
except OSError as e:
    if 'No such device' in str(e):
        print(f'{Style.BRIGHT}{Fore.RED}Error: Interface {args.interface} doesnt exist. \nPlease provide a valid interface name.{Style.RESET_ALL}')

        os.abort()

    else:
        raise
except KeyboardInterrupt:
    pass
