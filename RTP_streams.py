from packet_classes import *
from utility import *


class RTP_Streams:
    ''' This class contains RTP streams. RTP stream includes RTP and RTCP packets.
        RTP streams are stored in a dictionary where key is a stream identificator
        and value is a list of packets that belong to the stream. Stream identificator
        is a tuple which contains source and destination IP, source and destination port
        and SSRC.

        Formally:
            streams = {(src_ip, dst_ip, src_port, dst_port, ssrc): [MyPacket, ...]}
    '''

    def __init__(self, rules):
        self.streams = {}   # dict of RTP streams
        self.rules = rules  # config settings

    def __iter__(self):
        return iter(self.streams.items())

    def add(self, packet_pair):
        ''' Adds packet to corresponding stream. Takes a pair where first field indicates whether it is a RTP packet
            or a RTCP packet and the second field is the packet itself.
        '''

        (is_rtp, packet) = packet_pair

        # adding packet to stream
        key = (packet.get_src_ip(), packet.get_dst_ip(), packet.get_src_port(), packet.get_dst_port(), RTP_packet.get_static_ssrc(packet.get_packet_data()))

        if key in self.streams: # stream found
            self.streams[key].append((is_rtp,packet))
        else:                   # stream has to be created first
            self.streams[key] = [(is_rtp,packet)]

    def stream_check(self):
        ''' Removes streams that are too short. There needs to be a certain ammount of packets in each stream. '''

        removed_streams = {key:value for (key,value) in self.streams.items() if len(self.streams[key]) < int(self.rules['ALL']['minimum_rtp_packets_in_stream'])}
        self.streams = {key:value for (key,value) in self.streams.items() if len(self.streams[key]) >= int(self.rules['ALL']['minimum_rtp_packets_in_stream'])}
        return removed_streams
            

    def print_streams(self):

        print("------------ RTP STREAMS -----------")
        for i,key in enumerate(self.streams):
            print("Stream ",i,": ", key[0]+" "+key[1]+" "+str(key[2])+" "+str(key[3])+" "+str(key[4]))
        print("------------------------------------")