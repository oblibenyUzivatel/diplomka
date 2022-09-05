from packet_classes import *
from utility import *
from per_stream import *


class S1:
    ''' This class is used for per-stream processing. It is the most basic one - only packets
        with exactly the same source, destination IP address and source, destination port
        will be put together. Therefore only packets from PC1 to PC2 on the same ports will
        have the same IP and port information after randomization. Packets from PC2 to PC1 will
        have different IP and port.

        The class contains a dictionary where key is a stream identificator and value is a list
        of packets that belong to the stream. Stream identificator is a tuple which contains
        source and destination IP, source and destination port.

        Formally:
            self.streams = {(src_ip, dst_ip, src_port, dst_port): [Packet1, ...]}
    '''

    def __init__(self, rules):
        self.streams = {}   # dict of streams
        self.rules = rules  # config settings

    def add(self, packet):
        ''' Adds packet to corresponding stream. '''

        key = (packet.get_src_ip(), packet.get_dst_ip(), packet.get_src_port(), packet.get_dst_port())

        if key in self.streams:             # if there already is a stream, to which the packet belongs
            self.streams[key].add(packet)
        else:                               # if there is no such stream, we need to create the stream first
            self.streams[key] = Per_stream(key, packet.is_IPv4(), self.rules)
            self.streams[key].add(packet)   # and then add the packet

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

        print("\n------------ S1 STREAMS -----------")
        for stream in self.streams.values():
            stream.print_streams()
        print("------------------------------------")