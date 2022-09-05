#!/usr/bin/env python

'''
    This file contains smaller useful functions that help with computations.
'''

# import python modules
import re
import random
from scapy.all import *
import ipaddress


def getTCPdataLength(packet):
    ''' Get length of TCP payload in bytes.
        Arguments:
            packet - the packet
        Returns:
            Length of TCP payload in bytes.
    '''

    if "TCP" not in packet:
        return False

    TCP_data_len = None
    if "IP" in packet:
        IP_data_len = int(packet["IP"].len) - int(packet["IP"].ihl) * 4
        TCP_data_len = IP_data_len - int(packet["TCP"].dataofs) * 4
    elif "IPv6" in packet:
        IP_data_len = len(packet["IPv6"].payload) # weaker check than IPv4
        
    return TCP_data_len

def get_nice_payload(payload):
    ''' Converts a raw payload to a list of integers. One int for every byte.

        Scapy represents payload in encrypted bytes type. This payload must be
        decrypted and stored in something readable - list of bytes. After modification
        is done, it must be converted back.

        Arguments:
            payload - encoded bytes type which contains UDP / TCP payload
        Returns:
            list of integers, one number for one byte of the payload
    '''

    hexstring = str(bytes_hex(payload))[2:-1]
    hexlist = re.findall('..',hexstring)
    return [int(octet,base=16) for octet in hexlist]

def get_ugly_payload(payload):
    ''' Converts a list of integers to a raw payload. Does the opposite than get_nice_payload.
        Arguments:
            payload - list of integers, one number for one byte of the payload
        Returns:
            encoded bytes type which contains UDP / TCP payload
    '''
    hexstringlist = ''.join([str(format(number, '02x')) for number in payload])
    return hex_bytes(hexstringlist)

def check_ipv4_or_ipv6(packet):
    ''' Checks which version of IP protocol packet uses.
        Arguments:
            packet - packet to be checked
        Returns:
            "IP"    -> IPv4 packet
            "IPv6"  -> IPv6 packet
            None    -> Other packet
    '''

    ip_protocol = None
    if "IP" in packet and packet["IP"].version == 4:
        ip_protocol = "IP"
    elif "IPv6" in packet and packet["IPv6"].version == 6:
        ip_protocol = "IPv6"
    
    return ip_protocol

def check_udp(packet):
    ''' Check if packet is using UDP protocol.
        Arguments:
            packet - packet to be checked
        Returns:
            "UDP"   -> UDP protocol
            None    -> other protocol
    '''

    if "UDP" in packet:
        return "UDP"
    else:
        return None
    
    '''
    protocol = int(packet[ip_protocol].proto)
    if protocol != 17:
        return False
    '''

def check_udp_or_tcp(packet):
    ''' Check if packet is using UDP or TCP protocol.
        Arguments:
            packet - packet to be checked
        Returns:
            "UDP"   -> UDP protocol
            "TCP"   -> TCP protocol
            None    -> other protocol
    '''

    if "UDP" in packet:
        return "UDP"
    elif "TCP" in packet:
        return "TCP"
    else:
        return None

# randomization functions ----------------------------------------------------------

def get_rand_chance():
    return random.randint(1,100)

def get_rand_IP(part = 'both', mask_length = 0, prev_ip = None):

    if prev_ip != None:
        prev_ip = [int(x) for x in prev_ip.split('.')]
        prev_ip = (prev_ip[0] << 24) + (prev_ip[1] << 16) + (prev_ip[2] << 8) + prev_ip[3]        

    if part == 'both':
        result = random.randint(0,2**32-1)
    elif part == 'network':
        result = (random.randint(0,2**mask_length-1) << (32 - mask_length)) | (prev_ip & (2**(32-mask_length)-1))
    elif part == 'host':
        result = random.randint(0,2**(32-mask_length)-1) | ((prev_ip >> (32-mask_length)) << (32-mask_length))

    return ipaddress.IPv4Address(result)

# MASK LENGTH CANNOT BE 128!
def get_rand_IPv6(part = 'both', mask_length = 0, prev_ip = None):

    letters = '0123456789ABCDEF'

    if part == 'both':

        ipv6 = ""

        for i in range(7):
            for j in range(4):
                l = random.choice(letters)
                ipv6 = ipv6 + l
            ipv6 = ipv6 + ':'
        
        for j in range(4):
                l = random.choice(letters)
                ipv6 = ipv6 + l

    elif part == 'network':
        
        ipv6 = []

        for _ in range(mask_length):
            ipv6.append(random.choice(letters))

        for i in range(128-mask_length):
            ipv6.append(prev_ip[mask_length+i])

        ipv6 = ':'.join([a+b+c+d for a,b,c,d in zip(ipv6[::4], ipv6[1::4], ipv6[2::4], ipv6[3::4])])


    elif part == 'host':
        
        ipv6 = []

        for i in range(mask_length):
            ipv6.append(prev_ip[i])

        for _ in range(128-mask_length):
            ipv6.append(random.choice(letters))

        ipv6 = ':'.join([a+b+c+d for a,b,c,d in zip(ipv6[::4], ipv6[1::4], ipv6[2::4], ipv6[3::4])])

    return ipv6

def get_rand_ssrc(min_value, max_value):
    return random.randint(min_value, max_value)