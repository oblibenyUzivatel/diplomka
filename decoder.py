#!/usr/bin/env python

'''
    This file contains the Decoder class. The main goal of a Decoder is to decode packets
    - use pattern matching on the highest layer (application layer) to find out what protocol
    is there. For every protocol that should be recognized by this script there must be a method
    which will implement pattern matching on packet data and will be able to decide if the
    packet's protocol corresponds to the method.
    Each method takes a packet that should be decoded and returns either True (protocol matched)
    or False (protocol does not match).
'''

# import other files
from scapy.all import *
from utility import *


class Decoder:

    @staticmethod
    def isRTCPpacket(packet):

        # check if packet uses IP protocol - returns None|IP|IPv6
        ip_protocol = check_ipv4_or_ipv6(packet)
        if ip_protocol is None:
            return False

        # check if packet is using UDP or TCP protocol
        transport_protocol = check_udp_or_tcp(packet)
        if transport_protocol == None:
            return False

        # check source port and destination port (both must be >1023)
        sport = int(packet[transport_protocol].sport)
        dport = int(packet[transport_protocol].dport)
        if sport <= 1023 or dport <= 1023:
            return False

        # list of UDP payload octets in decimal numbers
        packet_data = get_nice_payload(packet[transport_protocol].payload)
        # length of parsed packet
        if transport_protocol == "UDP":
            packet_length = int(packet[transport_protocol].len) - 8
        else:
            packet_length = getTCPdataLength(packet)
        
        # analyse the first rtcp packet
        # length
        minimal_length = 8
        if minimal_length > packet_length:
            return False

        # version check - must be 2
        version = (packet_data[0] >> 6) & 3
        if version != 2:
            return False
        
        # packet type check - must be 72 or 73 - SR or RR
        payload_type = (packet_data[1] & 0b01111111)
        if payload_type != 72 and payload_type != 73:
            return False
        
        # padding check - should be 0 in the first packet???
        if (packet_data[0] >> 5) & 1 == 1:
            return False
        
        # compute total length so far
        minimal_length = ((packet_data[2] << 8) + packet_data[3] + 1) * 4
        
        while minimal_length < packet_length:
            # parsing other packets
            if minimal_length + 8 > packet_length:
                return False

            # version check - must be 2
            version = (packet_data[minimal_length] >> 6) & 3
            
            if version != 2:
                return False
            # compute total length so far
            minimal_length = minimal_length + ((packet_data[minimal_length + 2] << 8) + packet_data[minimal_length + 3] + 1) * 4
        
        return minimal_length == packet_length
        #return True # comment out while cycle

    @staticmethod
    def isRTPpacket(packet):
        
        # check if packet uses IP protocol - returns None|IP|IPv6
        ip_protocol = check_ipv4_or_ipv6(packet)
        if ip_protocol is None:
            return False

        # check if packet is using UDP or TCP protocol
        transport_protocol = check_udp_or_tcp(packet)
        if transport_protocol == None:
            return False

        # check source port and destination port (both must be >1023)
        sport = int(packet[transport_protocol].sport)
        dport = int(packet[transport_protocol].dport)
        if sport <= 1023 or dport <= 1023:
            return False

        # list of UDP payload octets in decimal numbers
        packet_data = get_nice_payload(packet[transport_protocol].payload)
        # length of parsed packet
        if transport_protocol == "UDP":
            packet_length = int(packet[transport_protocol].len) - 8
        else:
            packet_length = getTCPdataLength(packet)
        
        # minimal length check - must be consistent with CC and X
        minimal_length = None
        try:
            # minimal_length = 12 + cscr * 4 (in bytes)
            minimal_length = 12 + (packet_data[0] & 7) * 4
            # plus extension? - problem with rtcp identification
            #if (packet_data[0] >> 4) & 1 == 1:
                #minimal_length = minimal_length + 4     # extension header length
                #minimal_length = minimal_length + ((packet_data[minimal_length - 2] << 8) + packet_data[minimal_length - 1])
        except:
            return False

        if packet_length < minimal_length:
            return False

        # version check - must be 2
        version = (packet_data[0] >> 6) & 3     
        if version != 2:
            return False

        # payload type check - must not be 72 or 73 + other conditions???
        payload_type = (packet_data[1] & 127)
        #print(payload_type)
        if payload_type == 72 or payload_type == 73:
            return False

        # padding check
        if (packet_data[0] >> 5) & 1 == 1:
            if packet_data[-1] + minimal_length > packet_length:
                return False

        return True

    @staticmethod
    def isSTUNpacket(packet):

        # check if packet uses UDP or TCP protocol
        transport_protocol = check_udp_or_tcp(packet)
        if transport_protocol == None:
            return False

        # get ports
        sport = int(packet[transport_protocol].sport)
        dport = int(packet[transport_protocol].dport)
        
        # list of UDP payload octets in decimal numbers
        packet_data = get_nice_payload(packet[transport_protocol].payload)
        # length of parsed packet
        if transport_protocol == "UDP":
            packet_length = int(packet[transport_protocol].len) - 8
        else:
            packet_length = getTCPdataLength(packet)

        # check source port and destination port (both must be >1023)???
        if sport <= 1023 or dport <= 1023:
            return False
        
        # minimal length check - must be 20 + length (bytes)
        minimal_length = None
        try:
            # minimal_length = 20 + length (in bytes)
            minimal_length = 20 + (packet_data[2] << 8) + packet_data[3]
        except:
            return False

        if packet_length != minimal_length:
            return False

        # last two bits of length must be 0
        last_bits = packet_data[3] & 3
        if last_bits != 0:
            return False

        # first two bits must be 0
        first_bits = (packet_data[0] >> 6) & 3
        if first_bits != 0:
            return False

        # magic cookie check - must be 0x2112A442 (in network byte order)
        if packet_data[4] != 0x21 or packet_data[5] != 0x12 or packet_data[6] != 0xA4 or packet_data[7] != 0x42:
            return False

        return True


    @staticmethod
    def parseTLSrecord(packet_data, current_byte):
        ''' Parses and checks correctness of a TLS record. '''

        try:
            record_type = packet_data[current_byte]
            record_version_major = packet_data[current_byte + 1]
            record_version_minor = packet_data[current_byte + 2]
            record_length = (packet_data[current_byte + 3] << 8) + packet_data[current_byte + 4]
            
            # type must be in interval <20,24>
            if record_type < 20 or record_type > 24:
                return (False,0)

            # protocol version: 254.253 - are there other versions?
            if record_version_major != 3 or (record_version_minor < 0 or record_version_minor > 4):
                return (False,0)

            current_byte = current_byte + 5 + record_length
        except:
            return (False,0)

        return (True,current_byte)

    @staticmethod
    def isTLSpacket(packet):

        # check if packet uses UDP or TCP protocol
        transport_protocol = check_udp_or_tcp(packet)
        if transport_protocol == None:
            return False

        packet_data = None
        packet_length = None

        # list of UDP payload octets in decimal numbers
        packet_data = get_nice_payload(packet[transport_protocol].payload)
        # length of parsed packet
        if transport_protocol == "UDP":
            packet_length = int(packet[transport_protocol].len) - 8
        else:
            packet_length = getTCPdataLength(packet)

        # if TCP packet does not have payload -> it is not a TLS packet
        if packet_length == 0:
            return False

        # check length of all records
        current_byte = 0
        return_value = True
        while current_byte < packet_length and return_value:
            (return_value,current_byte) = Decoder.parseTLSrecord(packet_data, current_byte)
        
        # check if length of records + headers is equal to total payload length + check errors
        if current_byte != packet_length or not return_value:
            return False
        
        return True

    @staticmethod
    def parseDTLSrecord(packet_data, current_byte):
        ''' Parses and checks correctness of a DTLS record. '''

        try:
            record_type = packet_data[current_byte]
            record_version_first = packet_data[current_byte + 1]
            record_version_second = packet_data[current_byte + 2]
            record_length = (packet_data[current_byte + 11] << 8) + packet_data[current_byte + 12]
            
            # type must be in interval <20,24>
            if record_type < 20 or record_type > 24:
                return (False,0)

            # protocol version: 254.253 - are there other versions?
            if record_version_first != 254 or (record_version_second < 252 or record_version_second > 255):
                return (False,0)

            current_byte = current_byte + 13 + record_length
        except:
            return (False,0)

        return (True,current_byte)

    @staticmethod
    def isDTLSpacket(packet):

        # check if packet uses UDP protocol
        if "UDP" not in packet:
            return False

        packet_data = None
        packet_length = None

        if "UDP" in packet: # redundant if for now

            # list of UDP payload octets in decimal numbers
            packet_data = get_nice_payload(packet["UDP"].payload)
            # length of parsed packet
            packet_length = int(packet["UDP"].len) - 8
        else:
            return False

        # if UDP packet does not have payload -> it is not a DTLS packet
        if packet_length == 0:
            return False

        # check length of all records
        current_byte = 0
        return_value = True
        while current_byte < packet_length and return_value:
            (return_value,current_byte) = Decoder.parseDTLSrecord(packet_data, current_byte)

        # check if length of records + headers is equal to total payload length + check errors
        if current_byte != packet_length or not return_value:
            return False

        return True

        #TODO DCCP, SCTP, SRTP version ???