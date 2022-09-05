from packet_classes import *
from utility import *
from per_stream import *


class S2:
    ''' This class is used for per-stream processing. It is the advanced one - packets
        with similar source, destination IP address and source, destination port
        will be put together. Similar means that source and destination IP or ports can be switched.
        Therefore both packets from PC1 to PC2 and from PC2 to PC1 using the same ports will
        have the same IP and port information after randomization. Communication between same PCs
        but on two or more sets of ports will result into different IP and port after randomization.

        The class contains a dictionary where key is a stream identificator and value is a list
        of packets that belong to the stream. Stream identificator is a tuple which contains
        source and destination IP, source and destination port. The difference between this class
        and S1 is in extended check whether the packet belongs to the stream but structurally is the same.

        Formally:
            self.streams = {(src_ip, dst_ip, src_port, dst_port): [Packet1, ...]}
    '''

    def __init__(self, rules):
        self.streams = {}   # dict of RTP streams
        self.rules = rules  # config settings

    def add(self, packet):
        ''' Adds packet to corresponding stream. '''

        key = (packet.get_src_ip(), packet.get_dst_ip(), packet.get_src_port(), packet.get_dst_port())
        packet_src_ip = packet.get_src_ip()
        packet_dst_ip = packet.get_dst_ip()
        packet_src_port = packet.get_src_port()
        packet_dst_port = packet.get_dst_port()

        # adding ip pairs and port pairs to dict - extended checking
        if (packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port) in self.streams:
            self.streams[(packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port)].add(packet)
        elif (packet_src_ip, packet_dst_ip, packet_dst_port, packet_src_port) in self.streams:
            self.streams[(packet_src_ip, packet_dst_ip, packet_dst_port, packet_src_port)].add(packet)
        elif (packet_dst_ip, packet_src_ip, packet_src_port, packet_dst_port) in self.streams:
            self.streams[(packet_dst_ip, packet_src_ip, packet_src_port, packet_dst_port)].add(packet)
        elif (packet_dst_ip, packet_src_ip, packet_dst_port, packet_src_port) in self.streams:
            self.streams[(packet_dst_ip, packet_src_ip, packet_dst_port, packet_src_port)].add(packet)
        else:   # if there is no corresponding stream, one needs to be created first
            self.streams[key] = Per_stream(key, packet.is_IPv4(), self.rules)
            self.streams[key].add(packet)

    def process_streams(self):
        ''' This method starts processing (randomization) of each found stream. '''

        for stream in self.streams.values():
            stream.process_streams()

    def get_packets(self):
        ''' This method returns all packets from all streams. Used before writing to pcap file. '''

        list = []

        for stream in self.streams.values():
            list = list + stream.get_packets()

        return list
            
    def print_streams(self):
        ''' Print all found streams. For debugging purposes. '''

        print("------------ STREAMS -----------")
        for stream in self.streams.values():
            stream.print_streams()
        print("------------------------------------")