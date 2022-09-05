from packet_classes import *
from utility import *
from per_stream import *


class S3:
    ''' This class is used for per-stream processing. It is the elite one - packets
        with similar source, destination IP address and source, destination port
        will be put together. Similar means that source and destination IP or ports can be switched.
        Therefore both packets from PC1 to PC2 and from PC2 to PC1 using the same ports will
        have the same IP and port information after randomization. Communication between same PCs
        but on two or more sets of ports will also be included and will have same IP addresses after
        randomization. Ports will be different.

        The class contains a dictionary where key is an IP stream identificator and value is a dictionary
        of port stream identificators. Value of the second dictionary is a list
        of packets that belong to the stream. IP stream identificator is a tuple which contains
        source and destination IP. Port stream identificator is a tuple which contains source and
        destination port.

        Formally:
            self.streams = {(src_ip, dst_ip): {(src_port, dst_port): [MyPacket, ...]}}
    '''

    def __init__(self, rules):
        self.streams = {}   # dict of RTP streams
        self.rules = rules  # config settings

    def add_ports(self, packet, dict):
        ''' Add packet to corresponding port stream. '''
        
        key_port = (packet.get_src_port(), packet.get_dst_port())
        packet_src_port = packet.get_src_port()
        packet_dst_port = packet.get_dst_port()

        # adding port pairs to dict
        if (packet_src_port, packet_dst_port) in dict: # found a corresponding stream
            dict[(packet_src_port,packet_dst_port)].add(packet)
        elif (packet_dst_port, packet_src_port) in dict:
            dict[(packet_dst_port,packet_src_port)].add(packet)
        else: # corresponding stream not found, one needs to be created first
            dict[key_port] = Per_stream((packet.get_src_ip(), packet.get_dst_ip(), packet_src_port, packet_dst_port), packet.is_IPv4(), self.rules)
            dict[key_port].add(packet)

    def add(self, packet):
        ''' Adds packet to corresponding IP stream. '''

        key_ip = (packet.get_src_ip(), packet.get_dst_ip())
        packet_src_ip = packet.get_src_ip()
        packet_dst_ip = packet.get_dst_ip()

        # adding ip pairs and port pairs to dict
        if (packet_src_ip, packet_dst_ip) in self.streams: # found a corresponding stream
            self.add_ports(packet, self.streams[(packet_src_ip,packet_dst_ip)])
        elif (packet_dst_ip, packet_src_ip) in self.streams:
            self.add_ports(packet, self.streams[(packet_dst_ip,packet_src_ip)])
        else: # corresponding stream not found, one needs to be created first
            self.streams[key_ip] = {}
            self.add_ports(packet, self.streams[key_ip])

    
    def process_streams(self):
        ''' This method starts processing (randomization) of each found stream. '''

        for (stream_ip,dict_ports) in self.streams.items():
            for (stream_ports,stream) in dict_ports.items():
                stream.process_streams()

    def get_packets(self):
        ''' This method returns all packets from all streams. Used before writing to pcap file. '''

        list = []

        for dict in self.streams.values():
            for stream in dict.values():
                list = list + stream.get_packets()

        return list
            
    def print_streams(self):
        ''' Print all found streams. For debugging purposes. '''

        print("------------ STREAMS -----------")
        for i,key_ip in enumerate(self.streams):
            print("IP_stream ",i,": ", key_ip[0]+" "+key_ip[1])
            for j, key_port in enumerate(self.streams[key_ip]):
                print("\tPort group ",j,": ", key_port[0]," ",key_port[1])
        print("------------------------------------")