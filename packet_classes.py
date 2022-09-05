'''
    This file contains MyPacket class as well as RTP_packet, RTCP_packet, STUN_packet, TLS_packet, DTLS_packet
    that inherit from MyPacket class. These classes wrap scapy packet representation and add additional functionality.
    Every class mainly contains functions for randomization of itself.
'''


from scapy.all import *
from utility import *
import random
from numpy import random as rnd


# some exceptions
class BadInternetProtocolException(Exception):
    pass
class BadTransportProtocolException(Exception):
    pass


class MyPacket:
    ''' Parental packet class from which other classes should inherit.
        Each child class represents an application layer protocol.
    '''

    def __init__(self, packet, rules, packet_data = None):
        self.packet = packet                                    # scapy packet structure
        if packet_data == None:
            if 'Raw' in packet:
                self.packet_data = get_nice_payload(packet['Raw'].load) # nice payload - list of bytes
            else:
                self.packet_data = []
        else:
            self.packet_data = packet_data
        self.rules = rules                                      # rules specified in config file

        transport_protocol = check_udp_or_tcp(packet)
        if transport_protocol == "UDP":
            self.payload_length = int(packet[transport_protocol].len) - 8
        else:
            self.payload_length = getTCPdataLength(packet)

    def recalculate_checksum(self):
        ''' Force Scapy to recompute checksums by deleting the fields. '''

        if "UDP" in self.packet:
            del (self.packet["UDP"].chksum)
        elif "TCP" in self.packet:
            del (self.packet["TCP"].chksum)
        
        if "IP" in self.packet:
            del (self.packet["IP"].chksum)
        

    def packet_to_write(self):
        if 'Raw' in self.packet:
            self.packet['Raw'].load = get_ugly_payload(self.packet_data)

        # IP checksum computation
        self.recalculate_checksum()

        return self.packet

    def duplicate(self):
        return self.clone()

    def randomize(self):
        pass

    # Used to choose the rigth section in config file
    def config_section(self):
        return 'Undefined'

    # SORT FUNCTIONS
    def __lt__(self, other):
        return float(self.packet.time) < float(other.packet.time)

    def __le__(self, other):
        return float(self.packet.time) <= float(other.packet.time)

    # GETTERS
    def get_internet_protocol(self):
        if "IP" in self.packet:
            return "IP"
        elif "IPv6" in self.packet:
            return "IPv6"
        else:
            raise BadInternetProtocolException

    def get_transport_protocol(self):
        if "UDP" in self.packet:
            return "UDP"
        elif "TCP" in self.packet:
            return "TCP"
        else:
            raise BadTransportProtocolException

    def get_src_ip(self):
        return self.packet[self.get_internet_protocol()].src

    def get_dst_ip(self):
        return self.packet[self.get_internet_protocol()].dst

    def get_src_port(self):
        return self.packet[self.get_transport_protocol()].sport

    def get_dst_port(self):
        return self.packet[self.get_transport_protocol()].dport

    def is_IPv4(self):
        return check_ipv4_or_ipv6(self.packet) == "IP"

    def is_IPv6(self):
        return check_ipv4_or_ipv6(self.packet) == "IPv6"

    def get_packet_data(self):
        return self.packet_data

    def get_time(self):
        return float(self.packet.time)

    # SETTERS
    def set_src_ip(self, ip):
        self.packet[check_ipv4_or_ipv6(self.packet)].src = ip

    def set_dst_ip(self, ip):
        self.packet[check_ipv4_or_ipv6(self.packet)].dst = ip

    def set_src_port(self, port):
        self.packet[self.get_transport_protocol()].sport = port

    def set_dst_port(self, port):
        self.packet[self.get_transport_protocol()].dport = port

    def set_time(self, time):
        self.packet.time = float(time)

    # HELP FUNCTIONS FOR RANDOMIZE
    def randomize_IP(self, packet_stream, src_ip, dst_ip, protocol_name):
        # SOURCE IP
        if packet_stream or int(self.rules[protocol_name]['source_ip_change_chance']) >= get_rand_chance():
            if self.is_IPv4():
                if src_ip == None:
                    self.set_src_ip(get_rand_IP(
                        self.rules[protocol_name]['ipv4_randomize_parts'],
                        int(self.rules[protocol_name]['ipv4_mask_length']),
                        self.get_src_ip()
                    ))
                else:
                    self.set_src_ip(src_ip)
            else:
                if src_ip == None:
                    self.set_src_ip(get_rand_IPv6(
                        self.rules[protocol_name]['ipv6_randomize_parts'],
                        int(self.rules[protocol_name]['ipv6_mask_length']),
                        self.get_src_ip()
                    ))
                else:
                    self.set_src_ip(src_ip)
        # DESTINATION IP
        if packet_stream or int(self.rules[protocol_name]['destination_ip_change_chance']) >= get_rand_chance():
            if self.is_IPv4():
                if dst_ip == None:
                    self.set_dst_ip(get_rand_IP(
                        self.rules[protocol_name]['ipv4_randomize_parts'],
                        int(self.rules[protocol_name]['ipv4_mask_length']),
                        self.get_dst_ip()
                    ))
                else:
                    self.set_dst_ip(dst_ip)
            else:
                if dst_ip == None:
                    self.set_dst_ip(get_rand_IPv6(
                        self.rules[protocol_name]['ipv6_randomize_parts'],
                        int(self.rules[protocol_name]['ipv6_mask_length']),
                        self.get_dst_ip()
                    ))
                else:
                    self.set_dst_ip(dst_ip)

    def randomize_port(self, packet_stream, src_port, dst_port, protocol_name):
        # SOURCE PORT
        if packet_stream or int(self.rules[protocol_name]['source_port_chance_change']) >= get_rand_chance():
            if src_port == None:
                self.set_src_port(random.randint(int(self.rules[protocol_name]['source_port_min']), int(self.rules[protocol_name]['source_port_max'])))
            else:
                self.set_src_port(src_port)
        # DESTINATION PORT
        if packet_stream or int(self.rules[protocol_name]['destination_port_chance_change']) >= get_rand_chance():
            if dst_port == None:
                self.set_dst_port(random.randint(int(self.rules[protocol_name]['destination_port_min']), int(self.rules[protocol_name]['destination_port_max'])))
            else:
                self.set_dst_port(dst_port)

    def randomize_time(self, packet_stream, time, protocol_name):

        if packet_stream or int(self.rules[protocol_name]['time_chance_change']) >= get_rand_chance():
            if time == None:
                if self.rules[protocol_name]['time_randomization_method'] == 'normal':
                    self.set_time(rnd.normal(self.get_time(), float(self.rules[protocol_name]['time_constant'])))
                elif self.rules[protocol_name]['time_randomization_method'] == 'direct':
                    self.set_time(self.get_time() + float(self.rules[protocol_name]['time_constant']))
            else:
                self.set_time(self.get_time() + time)

        return

        
class RTP_packet(MyPacket):
    
    def randomize(self, packet_stream = False, time=None, src_ip = None, dst_ip = None, src_port = None, dst_port = None, ssrc = None, payload_type = None,
                  version=None, padding=None, extension=None, csrc_count=None, marker=None, sequence=None, timestamp=None):
        
        # RANDOMIZE IP
        self.randomize_IP(packet_stream, src_ip, dst_ip, self.config_section())

        # RANDOMIZE PORT
        self.randomize_port(packet_stream, src_port, dst_port, self.config_section())

        # RANDOMIZE CAPTURE TIME
        self.randomize_time(packet_stream, time, self.config_section())

        # SSRC
        if packet_stream or int(self.rules['RTP']['ssrc_chance_change']) >= get_rand_chance():
            if ssrc == None:
                self.set_ssrc(random.randint(int(self.rules['RTP']['ssrc_min']), int(self.rules['RTP']['ssrc_max'])))
            else:
                self.set_ssrc(ssrc)
        # PAYLOAD TYPE
        if int(self.rules['RTP']['payload_type_chance_change']) >= get_rand_chance():
            if payload_type == None:
                number = random.randint(int(self.rules['RTP']['payload_type_min']), int(self.rules['RTP']['payload_type_max']))
                stop = 30
                while number >=72 and number <= 95:
                    number = random.randint(int(self.rules['RTP']['payload_type_min']), int(self.rules['RTP']['payload_type_max']))
                    stop = stop - 1
                    if stop == 0:
                        number = 0
                        break
                self.set_payload_type(number)
            else:
                self.set_payload_type(payload_type)

        # ADDITIONAL OPTIONS
        # VERSION
        if int(self.rules['RTP']['version_chance_change']) >= get_rand_chance():
            if version == None:
                self.set_version(random.randint(int(self.rules['RTP']['version_min']), int(self.rules['RTP']['version_max'])))
            else:
                self.set_version(version)
        # PADDING
        if int(self.rules['RTP']['padding_chance_change']) >= get_rand_chance():
            if padding == None:
                self.set_padding(random.randint(int(self.rules['RTP']['padding_min']), int(self.rules['RTP']['padding_max'])))
            else:
                self.set_padding(padding)
        # EXTENSION
        if int(self.rules['RTP']['extension_chance_change']) >= get_rand_chance():
            if extension == None:
                self.set_extension(random.randint(int(self.rules['RTP']['extension_min']), int(self.rules['RTP']['extension_max'])))
            else:
                self.set_extension(extension)
        # CSRC COUNT
        if int(self.rules['RTP']['csrc_count_chance_change']) >= get_rand_chance():
            if csrc_count == None:
                self.set_csrc_count(random.randint(int(self.rules['RTP']['csrc_count_min']), int(self.rules['RTP']['csrc_count_max'])))
            else:
                self.set_csrc_count(csrc_count)
        # MARKER
        if int(self.rules['RTP']['marker_chance_change']) >= get_rand_chance():
            if marker == None:
                self.set_marker(random.randint(int(self.rules['RTP']['marker_min']), int(self.rules['RTP']['marker_max'])))
            else:
                self.set_marker(marker)
        # SEQUENCE
        if int(self.rules['RTP']['sequence_chance_change']) >= get_rand_chance():
            if sequence == None:
                self.set_sequence(random.randint(int(self.rules['RTP']['sequence_min']), int(self.rules['RTP']['sequence_max'])))
            else:
                self.set_sequence(sequence)
        # TIMESTAMP
        if int(self.rules['RTP']['timestamp_chance_change']) >= get_rand_chance():
            if timestamp == None:
                self.set_timestamp(random.randint(int(self.rules['RTP']['timestamp_min']), int(self.rules['RTP']['timestamp_max'])))
            else:
                self.set_timestamp(timestamp)

        return

    def clone(self):
        return RTP_packet(self.packet.copy(), self.rules, self.packet_data[:])

    # Used to choose the rigth section in config file
    def config_section(self):
        return 'RTP'

    # SETTERS
    def set_ssrc(self, ssrc):
        self.packet_data[8] = (ssrc >> 24) & 0b11111111
        self.packet_data[9] = (ssrc >> 16) & 0b11111111
        self.packet_data[10] = (ssrc >> 8) & 0b11111111
        self.packet_data[11] = ssrc & 0b11111111

    def set_payload_type(self, payload_type):
        self.packet_data[1] = self.packet_data[1] & 0b10000000 | payload_type & 0b01111111

    def set_version(self, version):
        self.packet_data[0] = self.packet_data[0] & 0b00111111 | ((version & 0b11) << 6)

    def set_padding(self, padding):
        self.packet_data[0] = self.packet_data[0] & 0b11011111 | ((padding & 0b1) << 5)

    def set_extension(self, extension):
        self.packet_data[0] = self.packet_data[0] & 0b11101111 | ((extension & 0b1) << 4)

    def set_csrc_count(self, csrc_count):
        self.packet_data[0] = self.packet_data[0] & 0b11110000 | (csrc_count & 0b1111)

    def set_marker(self, marker):
        self.packet_data[1] = self.packet_data[1] & 0b01111111 | ((marker & 0b1) << 7)

    def set_sequence(self, sequence):
        self.packet_data[2] = (sequence >> 8) & 0b11111111
        self.packet_data[3] = sequence & 0b11111111

    def set_timestamp(self, timestamp):
        self.packet_data[4] = (timestamp >> 24) & 0b11111111
        self.packet_data[5] = (timestamp >> 16) & 0b11111111
        self.packet_data[6] = (timestamp >> 8) & 0b11111111
        self.packet_data[7] = timestamp & 0b11111111
        
    # GETTERS
    def get_ssrc(self):
        return (self.packet_data[8] << 24) + (self.packet_data[9] << 16) + (self.packet_data[10] << 8) + self.packet_data[11]

    @staticmethod
    def get_static_ssrc(packet_data):
        return (packet_data[8] << 24) + (packet_data[9] << 16) + (packet_data[10] << 8) + packet_data[11]

    # PRINT FUNCTION
    def print_packet(self):
        self.packet.show()
        print("RTP: ...vypsat obsah")
        print("Rules: ...vyspat pravidla?")

class RTCP_packet(MyPacket):
    
    def randomize(self, packet_stream = False, time=None, src_ip = None, dst_ip = None, src_port = None, dst_port = None, ssrc = None, packet_type1 = None, packet_type2 = None,
                  version=None, padding=None, reception_report_count=None, length=None):
        
        # RANDOMIZE IP
        self.randomize_IP(packet_stream, src_ip, dst_ip, self.config_section())

        # RANDOMIZE PORT
        self.randomize_port(packet_stream, src_port, dst_port, self.config_section())

        # RANDOMIZE CAPTURE TIME
        self.randomize_time(packet_stream, time, self.config_section())
        
        # RANDOMIZE EVERY RTCP HEADER
        offset = 0
        while offset < self.payload_length:
            
            if packet_stream or int(self.rules['RTP']['ssrc_chance_change']) >= get_rand_chance():
                if ssrc == None:
                    self.set_ssrc(random.randint(int(self.rules['RTP']['ssrc_min']), int(self.rules['RTP']['ssrc_max'])), offset)
                else:
                    self.set_ssrc(ssrc, offset)
            
            if int(self.rules['RTCP']['packet_type_chance_change']) >= get_rand_chance():
                if offset == 0: # first packet must be 200 or 201
                    if packet_type1 == None:
                        number = random.randint(200, 201)
                    else:
                        number = packet_type1
                else:
                    if packet_type2 == None:
                        number = random.randint(int(self.rules['RTCP']['packet_type_min']), int(self.rules['RTCP']['packet_type_max']))
                    else:
                        number = packet_type2
                self.set_packet_type(number, offset)

            # VERSION
            if int(self.rules['RTCP']['version_chance_change']) >= get_rand_chance():
                if version == None:
                    self.set_version(random.randint(int(self.rules['RTCP']['version_min']), int(self.rules['RTCP']['version_max'])), offset)
                else:
                    self.set_version(version, offset)
            # PADDING
            if int(self.rules['RTCP']['padding_chance_change']) >= get_rand_chance():
                if padding == None:
                    self.set_padding(random.randint(int(self.rules['RTCP']['padding_min']), int(self.rules['RTCP']['padding_max'])), offset)
                else:
                    self.set_padding(padding, offset)
            # RECEPTION REPORT COUNT
            if int(self.rules['RTCP']['reception_report_count_chance_change']) >= get_rand_chance():
                if reception_report_count == None:
                    self.set_reception_report_count(random.randint(int(self.rules['RTCP']['reception_report_count_min']), int(self.rules['RTCP']['reception_report_count_max'])), offset)
                else:
                    self.set_reception_report_count(reception_report_count, offset)
            # LENGTH
            if int(self.rules['RTCP']['length_chance_change']) >= get_rand_chance():
                if length == None:
                    self.set_length(random.randint(int(self.rules['RTCP']['length_min']), int(self.rules['RTCP']['length_max'])), offset)
                else:
                    self.set_length(length, offset)
            
            offset = offset + ((self.packet_data[2+offset] << 8) + self.packet_data[3+offset] + 1) * 4
            
        return

    def set_fields(self):
        pass # for future stream manipulation

    def clone(self):
        return RTCP_packet(self.packet.copy(), self.rules, self.packet_data[:])

    # Used to choose the rigth section in config file
    def config_section(self):
        return 'RTCP'

    # SETTERS
    def set_ssrc(self, ssrc, offset=0):
        self.packet_data[4+offset] = (ssrc >> 24) & 0b11111111
        self.packet_data[5+offset] = (ssrc >> 16) & 0b11111111
        self.packet_data[6+offset] = (ssrc >> 8) & 0b11111111
        self.packet_data[7+offset] = ssrc & 0b11111111

    def set_packet_type(self, packet_type, offset=0):
        self.packet_data[1+offset] = packet_type

    def set_version(self, version, offset):
        self.packet_data[0+offset] = self.packet_data[0+offset] & 0b00111111 | ((version & 0b11) << 6)

    def set_padding(self, padding, offset):
        self.packet_data[0+offset] = self.packet_data[0+offset] & 0b11011111 | ((padding & 0b1) << 5)

    def set_reception_report_count(self, reception_report_count, offset):
        self.packet_data[0+offset] = self.packet_data[0+offset] & 0b11100000 | (reception_report_count & 0b11111)

    def set_length(self, length, offset):
        self.packet_data[2+offset] = (length >> 8) & 0b11111111
        self.packet_data[3+offset] = length & 0b11111111
        
    # GETTERS
    def get_ssrc(self):
        return (self.packet_data[4] << 24) + (self.packet_data[5] << 16) + (self.packet_data[6] << 8) + self.packet_data[7]

    # PRINT FUNCTION
    def print_packet(self):
        self.packet.show()
        print("RTCP: ...vypsat obsah")
        print("Rules: ...vyspat pravidla?")

class STUN_packet(MyPacket):
    
    def randomize(self, packet_stream = False, time=None, src_ip = None, dst_ip = None, src_port = None, dst_port = None, transaction_id = None, message_type = None,
                  first=None, length=None, cookie=None):

        # transaction ID: 0 .. 2**96-1
        
        # RANDOMIZE IP
        self.randomize_IP(packet_stream, src_ip, dst_ip, self.config_section())

        # RANDOMIZE PORT
        self.randomize_port(packet_stream, src_port, dst_port, self.config_section())

        # RANDOMIZE CAPTURE TIME
        self.randomize_time(packet_stream, time, self.config_section())
        
        # TRANSACTION ID
        if packet_stream or int(self.rules['STUN']['transaction_id_chance_change']) >= get_rand_chance():
            if transaction_id == None:
                self.set_transaction_id(random.randint(int(self.rules['STUN']['transaction_id_min']), int(self.rules['STUN']['transaction_id_max'])))
            else:
                self.set_transaction_id(transaction_id)
        # MESSAGE TYPE CLASS
        if packet_stream or int(self.rules['STUN']['message_type_class_chance_change']) >= get_rand_chance():
            if message_type == None:
                cls = random.randint(int(self.rules['STUN']['message_type_class_min']), int(self.rules['STUN']['message_type_class_max']))
            else:
                cls = message_type
            self.set_message_type_class(cls)

        # ADDITIONAL OPTIONS
        # VERSION
        if int(self.rules['STUN']['first_chance_change']) >= get_rand_chance():
            if first == None:
                self.set_first(random.randint(int(self.rules['STUN']['first_min']), int(self.rules['STUN']['first_max'])))
            else:
                self.set_first(first)
        # LENGTH
        if int(self.rules['STUN']['length_chance_change']) >= get_rand_chance():
            if length == None:
                self.set_length(random.randint(int(self.rules['STUN']['length_min']), int(self.rules['STUN']['length_max'])))
            else:
                self.set_length(length)
        # COOKIE
        if int(self.rules['STUN']['cookie_chance_change']) >= get_rand_chance():
            if cookie == None:
                self.set_cookie(random.randint(int(self.rules['STUN']['cookie_min']), int(self.rules['STUN']['cookie_max'])))
            else:
                self.set_cookie(cookie)

        return

    def set_fields(self):
        pass # for future stream manipulation

    def clone(self):
        return STUN_packet(self.packet.copy(), self.rules, self.packet_data[:])

    # Used to choose the rigth section in config file
    def config_section(self):
        return 'STUN'

    # SETTERS
    def set_transaction_id(self, id):
        self.packet_data[8] = (id >> 11*8) & 0b11111111
        self.packet_data[9] = (id >> 10*8) & 0b11111111
        self.packet_data[10] = (id >> 9*8) & 0b11111111
        self.packet_data[11] = (id >> 8*8) & 0b11111111
        self.packet_data[12] = (id >> 7*8) & 0b11111111
        self.packet_data[13] = (id >> 6*8) & 0b11111111
        self.packet_data[14] = (id >> 5*8) & 0b11111111
        self.packet_data[15] = (id >> 4*8) & 0b11111111
        self.packet_data[16] = (id >> 3*8) & 0b11111111
        self.packet_data[17] = (id >> 2*8) & 0b11111111
        self.packet_data[18] = (id >> 1*8) & 0b11111111
        self.packet_data[19] = id & 0b11111111

    def set_message_type_class(self, cls):
        self.packet_data[0] = (self.packet_data[0] & 0b11111110) + (cls & 0b00000001)
        self.packet_data[1] = (self.packet_data[1] & 0b11101111) + ((cls & 0b00000010) << 3)

    def set_first(self, first):
        self.packet_data[0] = self.packet_data[0] & 0b00111111 | ((first & 0b11) << 6)

    def set_length(self, length):
        self.packet_data[2] = (length >> 8) & 0b11111111
        self.packet_data[3] = length & 0b11111111

    def set_cookie(self, cookie):
        self.packet_data[4] = (cookie >> 24) & 0b11111111
        self.packet_data[5] = (cookie >> 16) & 0b11111111
        self.packet_data[6] = (cookie >> 8) & 0b11111111
        self.packet_data[7] = cookie & 0b11111111
        
    # GETTERS

    # PRINT FUNCTION
    def print_packet(self):
        self.packet.show()
        print("RTP: ...vypsat obsah")
        print("Rules: ...vyspat pravidla?")

class TLS_packet(MyPacket):
    
    def randomize_handshake(self, offset, handshake_type, hnd_length):
        
        # HANDSHAKE TYPE
        if int(self.rules['TLS']['handshake_type_chance_change']) >= get_rand_chance():
            if handshake_type == None:
                self.set_handshake_type(random.randint(int(self.rules['TLS']['handshake_type_min']), int(self.rules['TLS']['handshake_type_max'])), offset)
            else:
                self.set_handshake_type(handshake_type, offset)
        # LENGTH
        if int(self.rules['TLS']['hnd_length_chance_change']) >= get_rand_chance():
            if hnd_length == None:
                self.set_hnd_length(random.randint(int(self.rules['TLS']['hnd_length_min']), int(self.rules['TLS']['hnd_length_max'])), offset)
            else:
                self.set_hnd_length(hnd_length, offset)
        
        return

    def randomize(self, packet_stream = False, time=None, src_ip = None, dst_ip = None, src_port = None, dst_port = None,
                  content_type=None, legacy_version=None, length=None, hnd_message_type=None, hnd_length=None):
        
        # RANDOMIZE IP
        self.randomize_IP(packet_stream, src_ip, dst_ip, self.config_section())

        # RANDOMIZE PORT
        self.randomize_port(packet_stream, src_port, dst_port, self.config_section())

        # RANDOMIZE CAPTURE TIME
        self.randomize_time(packet_stream, time, self.config_section())

        # RANDOMIZE EVERY TLS RECORD
        offset = 0
        while offset < self.payload_length:

            # randomize header if it is a handshake
            if self.packet_data[0+offset] == 22:
                self.randomize_handshake(offset+5, hnd_message_type, hnd_length)

            # CONTENT TYPE
            if int(self.rules['TLS']['content_type_chance_change']) >= get_rand_chance():
                if content_type == None:
                    self.set_content_type(random.randint(int(self.rules['TLS']['content_type_min']), int(self.rules['TLS']['content_type_max'])), offset)
                else:
                    self.set_content_type(content_type, offset)
            # LEGACY VERSION
            if int(self.rules['TLS']['legacy_version_chance_change']) >= get_rand_chance():
                if legacy_version == None:
                    self.set_legacy_version(random.randint(int(self.rules['TLS']['legacy_version_min']), int(self.rules['TLS']['legacy_version_max'])), offset)
                else:
                    self.set_legacy_version(legacy_version, offset)
            # LENGTH
            if int(self.rules['TLS']['length_chance_change']) >= get_rand_chance():
                if length == None:
                    self.set_length(random.randint(int(self.rules['TLS']['length_min']), int(self.rules['TLS']['length_max'])), offset)
                else:
                    self.set_length(length, offset)
            
            # adding length of header and length of payload
            offset = offset + 5 + ((self.packet_data[3+offset] << 8) + self.packet_data[4+offset])

        return

    def clone(self):
        return TLS_packet(self.packet.copy(), self.rules, self.packet_data[:])

    def is_handshake(self):
        return self.packet_data[0] == 22

    # Used to choose the rigth section in config file
    def config_section(self):
        return 'TLS'

    # SETTERS
    def set_content_type(self, content_type, offset):
        self.packet_data[0+offset] = content_type & 0b11111111

    def set_legacy_version(self, legacy_version, offset):
        self.packet_data[1+offset] = (legacy_version >> 8) & 0b11111111
        self.packet_data[2+offset] = legacy_version & 0b11111111

    def set_length(self, length, offset):
        self.packet_data[3+offset] = (length >> 8) & 0b11111111
        self.packet_data[4+offset] = length & 0b11111111

    # hnd methods
    def set_handshake_type(self, handshake_type, offset):
        self.packet_data[0+offset] = handshake_type & 0b11111111

    def set_hnd_length(self, hnd_length, offset):
        self.packet_data[1+offset] = (hnd_length >> 16) & 0b11111111
        self.packet_data[2+offset] = (hnd_length >> 8) & 0b11111111
        self.packet_data[3+offset] = hnd_length & 0b11111111
        
    # GETTERS

    # PRINT FUNCTION
    def print_packet(self):
        self.packet.show()
        print("TLS: ...vypsat obsah")
        print("Rules: ...vypsat pravidla?")

class DTLS_packet(MyPacket):
    
    def randomize_handshake(self, offset, handshake_type, hnd_length, hnd_message_seq, hnd_fragment_offset, hnd_fragment_length):
        
        # HANDSHAKE TYPE
        if int(self.rules['DTLS']['handshake_type_chance_change']) >= get_rand_chance():
            if handshake_type == None:
                self.set_handshake_type(random.randint(int(self.rules['DTLS']['handshake_type_min']), int(self.rules['DTLS']['handshake_type_max'])), offset)
            else:
                self.set_handshake_type(handshake_type, offset)
        # LENGTH
        if int(self.rules['DTLS']['hnd_length_chance_change']) >= get_rand_chance():
            if hnd_length == None:
                self.set_hnd_length(random.randint(int(self.rules['DTLS']['hnd_length_min']), int(self.rules['DTLS']['hnd_length_max'])), offset)
            else:
                self.set_hnd_length(hnd_length, offset)
        # MESSAGE_SEQ
        if int(self.rules['DTLS']['message_seq_chance_change']) >= get_rand_chance():
            if hnd_message_seq == None:
                self.set_hnd_message_seq(random.randint(int(self.rules['DTLS']['message_seq_min']), int(self.rules['DTLS']['message_seq_max'])), offset)
            else:
                self.set_hnd_message_seq(hnd_message_seq, offset)
        # FRAGMENT OFFSET
        if int(self.rules['DTLS']['fragment_offset_chance_change']) >= get_rand_chance():
            if hnd_fragment_offset == None:
                self.set_hnd_fragment_offset(random.randint(int(self.rules['DTLS']['fragment_offset_min']), int(self.rules['DTLS']['fragment_offset_max'])), offset)
            else:
                self.set_hnd_fragment_offset(hnd_fragment_offset, offset)
        # FRAGMENT LENGTH
        if int(self.rules['DTLS']['fragment_length_chance_change']) >= get_rand_chance():
            if hnd_fragment_length == None:
                self.set_hnd_fragment_length(random.randint(int(self.rules['DTLS']['fragment_length_min']), int(self.rules['DTLS']['fragment_length_max'])), offset)
            else:
                self.set_hnd_fragment_length(hnd_fragment_length, offset)
        
        return

    def randomize(self, packet_stream = False, time=None, src_ip = None, dst_ip = None, src_port = None, dst_port = None,
                  content_type=None, legacy_version=None, epoch=None, sequence_number=None, length=None,
                  hnd_message_type=None, hnd_length=None, hnd_message_seq=None, hnd_fragment_offset=None, hnd_fragment_length=None):
        
        # RANDOMIZE IP
        self.randomize_IP(packet_stream, src_ip, dst_ip, self.config_section())

        # RANDOMIZE PORT
        self.randomize_port(packet_stream, src_port, dst_port, self.config_section())

        # RANDOMIZE CAPTURE TIME
        self.randomize_time(packet_stream, time, self.config_section())

        # RANDOMIZE EVERY DTLS RECORD
        offset = 0
        while offset < self.payload_length:

            # randomize header if it is a handshake
            if self.packet_data[0+offset] == 22:
                self.randomize_handshake(offset+13, hnd_message_type, hnd_length, hnd_message_seq, hnd_fragment_offset, hnd_fragment_length)

            # CONTENT TYPE
            if int(self.rules['DTLS']['content_type_chance_change']) >= get_rand_chance():
                if content_type == None:
                    self.set_content_type(random.randint(int(self.rules['DTLS']['content_type_min']), int(self.rules['DTLS']['content_type_max'])), offset)
                else:
                    self.set_content_type(content_type, offset)
            # LEGACY VERSION
            if int(self.rules['DTLS']['legacy_version_chance_change']) >= get_rand_chance():
                if legacy_version == None:
                    self.set_legacy_version(random.randint(int(self.rules['DTLS']['legacy_version_min']), int(self.rules['DTLS']['legacy_version_max'])), offset)
                else:
                    self.set_legacy_version(legacy_version, offset)
            # EPOCH
            if int(self.rules['DTLS']['epoch_chance_change']) >= get_rand_chance():
                if epoch == None:
                    self.set_epoch(random.randint(int(self.rules['DTLS']['epoch_min']), int(self.rules['DTLS']['epoch_max'])), offset)
                else:
                    self.set_epoch(epoch, offset)
            # SEQUENCE NUMBER
            if int(self.rules['DTLS']['sequence_number_chance_change']) >= get_rand_chance():
                if sequence_number == None:
                    self.set_sequence_number(random.randint(int(self.rules['DTLS']['sequence_number_min']), int(self.rules['DTLS']['sequence_number_max'])), offset)
                else:
                    self.set_sequence_number(sequence_number, offset)
            # LENGTH
            if int(self.rules['DTLS']['length_chance_change']) >= get_rand_chance():
                if length == None:
                    self.set_length(random.randint(int(self.rules['DTLS']['length_min']), int(self.rules['DTLS']['length_max'])), offset)
                else:
                    self.set_length(length, offset)
            
            # adding length of header and length of payload
            offset = offset + 13 + ((self.packet_data[11+offset] << 8) + self.packet_data[12+offset])

        return

    def clone(self):
        return DTLS_packet(self.packet.copy(), self.rules, self.packet_data[:])

    def is_handshake(self):
        return self.packet_data[0] == 22

    # Used to choose the rigth section in config file
    def config_section(self):
        return 'DTLS'

    # SETTERS
    def set_content_type(self, content_type, offset):
        self.packet_data[0+offset] = content_type & 0b11111111

    def set_legacy_version(self, legacy_version, offset):
        self.packet_data[1+offset] = (legacy_version >> 8) & 0b11111111
        self.packet_data[2+offset] = legacy_version & 0b11111111

    def set_epoch(self, epoch, offset):
        self.packet_data[3+offset] = (epoch >> 8) & 0b11111111
        self.packet_data[4+offset] = epoch & 0b11111111

    def set_sequence_number(self, sequence_number, offset):
        self.packet_data[5+offset] = (sequence_number >> 40) & 0b11111111
        self.packet_data[6+offset] = (sequence_number >> 32) & 0b11111111
        self.packet_data[7+offset] = (sequence_number >> 24) & 0b11111111
        self.packet_data[8+offset] = (sequence_number >> 16) & 0b11111111
        self.packet_data[9+offset] = (sequence_number >> 8) & 0b11111111
        self.packet_data[10+offset] = sequence_number & 0b11111111

    def set_length(self, length, offset):
        self.packet_data[11+offset] = (length >> 8) & 0b11111111
        self.packet_data[12+offset] = length & 0b11111111

    # hnd methods
    def set_handshake_type(self, handshake_type, offset):
        self.packet_data[0+offset] = handshake_type & 0b11111111

    def set_hnd_length(self, hnd_length, offset):
        self.packet_data[1+offset] = (hnd_length >> 16) & 0b11111111
        self.packet_data[2+offset] = (hnd_length >> 8) & 0b11111111
        self.packet_data[3+offset] = hnd_length & 0b11111111

    def set_hnd_message_seq(self, hnd_message_seq, offset):
        self.packet_data[4+offset] = (hnd_message_seq >> 8) & 0b11111111
        self.packet_data[5+offset] = hnd_message_seq & 0b11111111

    def set_hnd_fragment_offset(self, hnd_fragment_offset, offset):
        self.packet_data[6+offset] = (hnd_fragment_offset >> 16) & 0b11111111
        self.packet_data[7+offset] = (hnd_fragment_offset >> 8) & 0b11111111
        self.packet_data[8+offset] = hnd_fragment_offset & 0b11111111

    def set_hnd_fragment_length(self, hnd_fragment_length, offset):
        self.packet_data[9+offset] = (hnd_fragment_length >> 16) & 0b11111111
        self.packet_data[10+offset] = (hnd_fragment_length >> 8) & 0b11111111
        self.packet_data[11+offset] = hnd_fragment_length & 0b11111111
        
    # GETTERS

    # PRINT FUNCTION
    def print_packet(self):
        self.packet.show()
        print("DTLS: ...vypsat obsah")
        print("Rules: ...vypsat pravidla?")