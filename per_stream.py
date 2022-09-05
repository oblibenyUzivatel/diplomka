from RTP_streams import RTP_Streams
from packet_classes import *
from utility import *
import random
from numpy import random as rnd


class Per_stream:
    ''' This class further divides packets into substreams based on their protocol after
        they have been divided by IP and port addresses. Each protocol can also be divided
        even more, for example RTP/RTCP (using SSRC).

        This class also implements the per-stream randomization of all packets.
    '''

    def __init__(self, basic_key, is_ipv4, rules):
        self.rtp_streams = {}   # dict of RTP streams (rtp+rtcp; based on ssrc)
        self.stun_streams = {}  # dict of stun streams (for now only one stream)
        self.tls_streams = {}   # dict os tls streams (for now only one stream)
        self.dtls_streams = {}  # dict of dtls streams (for now only one stream)
        self.other_packets = {} # fict of other packet streams (for now only one stream)
        self.basic_key = basic_key  # (src_ip, dst_ip, src_port, dst_port)
        self.is_ipv4 = is_ipv4  # indicates if stream is ipv4
        self.rules = rules      # config settings


    def add(self, packet):
        # adding packet to corresponding stream
        if isinstance(packet, RTP_packet) or isinstance(packet, RTCP_packet):
            key = (packet.get_ssrc(),0)
            if key in self.rtp_streams:
                self.rtp_streams[key].append(packet)
            else:
                self.rtp_streams[key] = [packet]

        elif isinstance(packet, STUN_packet):
            key = (None,0)
            if key in self.stun_streams:
                self.stun_streams[key].append(packet)
            else:
                self.stun_streams[key] = [packet]

        elif isinstance(packet, TLS_packet):
            key = (None,0)
            if key in self.tls_streams:
                self.tls_streams[key].append(packet)
            else:
                self.tls_streams[key] = [packet]

        elif isinstance(packet, DTLS_packet):
            key = (None,0)
            if key in self.dtls_streams:
                self.dtls_streams[key].append(packet)
            else:
                self.dtls_streams[key] = [packet]

        else:
            key = (None,0)
            if key in self.other_packets:
                self.other_packets[key].append(packet)
            else:
                self.other_packets[key] = [packet]

    def generate_conversion_dict(self, protocol):
        ''' Used to generate conversion dict that will be used for fast randomization. '''

        conversion_dict = {}    # used for easy conversions, key = former value, value = new value

        if self.is_ipv4:
            conversion_dict[self.basic_key[0]] = get_rand_IP(
                self.rules[protocol]['ipv4_randomize_parts'],
                int(self.rules[protocol]['ipv4_mask_length']),
                self.basic_key[0]
            )
            conversion_dict[self.basic_key[1]] = get_rand_IP(
                self.rules[protocol]['ipv4_randomize_parts'],
                int(self.rules[protocol]['ipv4_mask_length']),
                self.basic_key[1]
            )
        else:
            conversion_dict[self.basic_key[0]] = get_rand_IPv6(
                self.rules[protocol]['ipv6_randomize_parts'],
                int(self.rules[protocol]['ipv6_mask_length']),
                self.basic_key[0]
            )
            conversion_dict[self.basic_key[1]] = get_rand_IPv6(
                self.rules[protocol]['ipv6_randomize_parts'],
                int(self.rules[protocol]['ipv6_mask_length']),
                self.basic_key[1]
            )

        conversion_dict[self.basic_key[2]] = random.randint(int(self.rules[protocol]['source_port_min']), int(self.rules[protocol]['source_port_max']))
        conversion_dict[self.basic_key[3]] = random.randint(int(self.rules[protocol]['destination_port_min']), int(self.rules[protocol]['destination_port_max']))

        if int(self.rules[protocol]['time_chance_change']) >= get_rand_chance():
            if self.rules[protocol]['time_randomization_method'] == 'normal':
                conversion_dict['time_offset'] = float(rnd.normal(0.0, float(self.rules[protocol]['time_constant'])))
            elif self.rules[protocol]['time_randomization_method'] == 'direct':
                conversion_dict['time_offset'] = float(self.rules[protocol]['time_constant'])
            else:
                conversion_dict['time_offset'] = float(0.0)
        else:
            conversion_dict['time_offset'] = float(0.0)

        return conversion_dict

    # --------------------------------------------------------------------------------------------------

    def protocol_based_randomization(self, packet, new_time, new_src_ip, new_dst_ip, new_src_port, new_dst_port, new_ssrc):

        if packet.config_section() == 'RTP':
            packet.randomize(packet_stream = True, time = new_time, src_ip = new_src_ip, dst_ip = new_dst_ip, src_port = new_src_port, dst_port = new_dst_port,\
                             ssrc = new_ssrc, payload_type = None)
        if packet.config_section() == 'STUN':
            packet.randomize(packet_stream = True, time = new_time, src_ip = new_src_ip, dst_ip = new_dst_ip, src_port = new_src_port, dst_port = new_dst_port,\
                             transaction_id = None, message_type = None)
        if packet.config_section() == 'TLS':
            packet.randomize(packet_stream = True, time = new_time, src_ip = new_src_ip, dst_ip = new_dst_ip, src_port = new_src_port, dst_port = new_dst_port)
        if packet.config_section() == 'DTLS':
            packet.randomize(packet_stream = True, time = new_time, src_ip = new_src_ip, dst_ip = new_dst_ip, src_port = new_src_port, dst_port = new_dst_port)

    def process_packets_in_stream(self, stream, conversion_dict, new_ssrc=None):

        new_stream = []

        for packet in stream:

            # remove packet
            if int(self.rules[packet.config_section()]['delete_packet_chance']) >= get_rand_chance():
                continue

            new_src_ip = conversion_dict[packet.get_src_ip()]
            new_dst_ip = conversion_dict[packet.get_dst_ip()]
            new_src_port = conversion_dict[packet.get_src_port()]
            new_dst_port = conversion_dict[packet.get_dst_port()]
            new_time = conversion_dict['time_offset']

            # packet duplication version 1
            if int(self.rules[packet.config_section()]['duplication_version']) == 1:
                if int(self.rules[packet.config_section()]['duplicate_packet_chance']) >= get_rand_chance():
                    new_packet = packet.duplicate()
                    self.protocol_based_randomization(new_packet, new_time, new_src_ip, new_dst_ip, new_src_port, new_dst_port, new_ssrc)
                    new_stream.append(new_packet)
                self.protocol_based_randomization(packet, new_time, new_src_ip, new_dst_ip, new_src_port, new_dst_port, new_ssrc)
                new_stream.append(packet)

            # packet duplication version 2
            elif int(self.rules[packet.config_section()]['duplication_version']) == 2:
                self.protocol_based_randomization(packet, new_time, new_src_ip, new_dst_ip, new_src_port, new_dst_port, new_ssrc)
                new_stream.append(packet)
                if int(self.rules[packet.config_section()]['duplicate_packet_chance']) >= get_rand_chance():
                    new_packet = packet.duplicate()
                    new_stream.append(new_packet)

        return new_stream

    # --------------------------------------------------------------------------------------------------

    # Following classes define, how should streams be randomized. They provide tools
    # to implement per-stream randomization of certain fields but also per-packet
    # randomization of other fields.
    def process_rtp_streams(self):

        # generate conversion dict for fast randomization
        base_conversion_dict = self.generate_conversion_dict('RTP')

        # for every rtp/rtcp stream perform randomization based on conversion dict and protocol specific values
        for (stream_name,stream) in self.rtp_streams.items():

            if stream_name[-1] != 0:                                    # if the stream is duplicated and needs to have different IP and ports
                conversion_dict = self.generate_conversion_dict('RTP')
            else:                                                       # if the stream is not duplicated, use base dict
                conversion_dict = base_conversion_dict
            
            new_ssrc = get_rand_ssrc(int(self.rules['RTP']['ssrc_min']), int(self.rules['RTP']['ssrc_max']))

            #if self.rules['ALL']['randomize_duplicated_packets'] == "True" and stream_name[-1] != 0: # broken, dont use
                #self.process_packets_in_stream(stream, conversion_dict, new_ssrc) # created packets need to be saved in self.rtp_streams
            #else:
            for packet in stream:

                new_src_ip = conversion_dict[packet.get_src_ip()]
                new_dst_ip = conversion_dict[packet.get_dst_ip()]
                new_src_port = conversion_dict[packet.get_src_port()]
                new_dst_port = conversion_dict[packet.get_dst_port()]
                new_time = conversion_dict['time_offset']

                packet.randomize(packet_stream = True, time = new_time, src_ip = new_src_ip, dst_ip = new_dst_ip, src_port = new_src_port, dst_port = new_dst_port,\
                                ssrc = new_ssrc)
            

    def process_stun_streams(self):

        base_conversion_dict = self.generate_conversion_dict('STUN')

        # for every stun stream perform randomization based on conversion dict and protocol specific values
        for (stream_name,stream) in self.stun_streams.items():

            if stream_name[-1] != 0:                                    # if the stream is duplicated and needs to have different IP and ports
                conversion_dict = self.generate_conversion_dict('STUN')
            else:                                                       # if the stream is not duplicated, use base dict
                conversion_dict = base_conversion_dict

            #if self.rules['ALL']['randomize_duplicated_packets'] == "True" and stream_name[-1] != 0:
            #    self.process_packets_in_stream(stream, conversion_dict)
            #else:
            for packet in stream:

                new_src_ip = conversion_dict[packet.get_src_ip()]
                new_dst_ip = conversion_dict[packet.get_dst_ip()]
                new_src_port = conversion_dict[packet.get_src_port()]
                new_dst_port = conversion_dict[packet.get_dst_port()]
                new_time = conversion_dict['time_offset']

                packet.randomize(packet_stream = True, time = new_time, src_ip = new_src_ip, dst_ip = new_dst_ip, src_port = new_src_port, dst_port = new_dst_port,\
                                transaction_id = None, message_type = None)

    def process_tls_streams(self):

        base_conversion_dict = self.generate_conversion_dict('TLS')

        # for every tls stream perform randomization based on conversion dict and protocol specific values
        for (stream_name,stream) in self.tls_streams.items():

            if stream_name[-1] != 0:                                    # if the stream is duplicated and needs to have different IP and ports
                conversion_dict = self.generate_conversion_dict('TLS')
            else:                                                       # if the stream is not duplicated, use base dict
                conversion_dict = base_conversion_dict

            #if self.rules['ALL']['randomize_duplicated_packets'] == "True" and stream_name[-1] != 0:
            #    self.process_packets_in_stream(stream, conversion_dict)
            #else:
            for packet in stream:

                new_src_ip = conversion_dict[packet.get_src_ip()]
                new_dst_ip = conversion_dict[packet.get_dst_ip()]
                new_src_port = conversion_dict[packet.get_src_port()]
                new_dst_port = conversion_dict[packet.get_dst_port()]
                new_time = conversion_dict['time_offset']

                packet.randomize(packet_stream = True, time = new_time, src_ip = new_src_ip, dst_ip = new_dst_ip, src_port = new_src_port, dst_port = new_dst_port)
    
    def process_dtls_streams(self):

        base_conversion_dict = self.generate_conversion_dict('DTLS')

        # for every dtls stream perform randomization based on conversion dict and protocol specific values
        for (stream_name,stream) in self.dtls_streams.items():

            if stream_name[-1] != 0:                                    # if the stream is duplicated and needs to have different IP and ports
                conversion_dict = self.generate_conversion_dict('DTLS')
            else:                                                       # if the stream is not duplicated, use base dict
                conversion_dict = base_conversion_dict

            #if self.rules['ALL']['randomize_duplicated_packets'] == "True" and stream_name[-1] != 0:
            #    self.process_packets_in_stream(stream, conversion_dict)
            #else:
            for packet in stream:

                new_src_ip = conversion_dict[packet.get_src_ip()]
                new_dst_ip = conversion_dict[packet.get_dst_ip()]
                new_src_port = conversion_dict[packet.get_src_port()]
                new_dst_port = conversion_dict[packet.get_dst_port()]
                new_time = conversion_dict['time_offset']

                packet.randomize(packet_stream = True, time = new_time, src_ip = new_src_ip, dst_ip = new_dst_ip, src_port = new_src_port, dst_port = new_dst_port)
    

    def process_streams(self):
        ''' Performs stream duplication and deletion. Starts per-stream randomization. '''

        # optimization
        if int(self.rules['ALL']['delete_stream_chance']) > 0:
            self.remove_streams()

        if int(self.rules['ALL']['stream_duplication_version']) == 1:
            # optimization
            if int(self.rules['ALL']['duplicate_stream_chance']) > 0:
                self.duplicate_streams()

        self.process_rtp_streams()
        self.process_stun_streams()
        self.process_tls_streams()
        self.process_dtls_streams()

        if int(self.rules['ALL']['stream_duplication_version']) == 2:
            # optimization
            if int(self.rules['ALL']['duplicate_stream_chance']) > 0:
                self.duplicate_streams()

    def remove_streams(self):
        ''' Deletes streams based on chance (from config file). '''

        new_rtp_streams = {}
        new_stun_streams = {}
        new_tls_streams = {}
        new_dtls_streams = {}
        new_other_packets = {}

        for (stream_name,stream) in self.rtp_streams.items():
            if int(self.rules['ALL']['delete_stream_chance']) < get_rand_chance():
                new_rtp_streams[stream_name] = stream

        for (stream_name,stream) in self.stun_streams.items():
            if int(self.rules['ALL']['delete_stream_chance']) < get_rand_chance():
                new_stun_streams[stream_name] = stream

        for (stream_name,stream) in self.tls_streams.items():
            if int(self.rules['ALL']['delete_stream_chance']) < get_rand_chance():
                new_tls_streams[stream_name] = stream

        for (stream_name,stream) in self.dtls_streams.items():
            if int(self.rules['ALL']['delete_stream_chance']) < get_rand_chance():
                new_dtls_streams[stream_name] = stream

        for (stream_name,stream) in self.other_packets.items():
            if int(self.rules['ALL']['delete_stream_chance']) < get_rand_chance():
                new_other_packets[stream_name] = stream

        self.rtp_streams = new_rtp_streams
        self.stun_streams = new_stun_streams
        self.tls_streams = new_tls_streams
        self.dtls_streams = new_dtls_streams
        self.other_packets = new_other_packets

    def duplicate_streams(self):
        ''' Duplicates streams based on chance (from config file). '''

        new_rtp_streams = {}

        for (stream_name,stream) in self.rtp_streams.items():

            new_rtp_streams[stream_name] = stream   # put original stream in

            for duplication_number in range(1, 1 + int(self.rules['ALL']['duplication_number'])):
                if int(self.rules['ALL']['duplicate_stream_chance']) >= get_rand_chance():
                    new_stream_key = (stream_name[0],duplication_number)
                    new_stream = [packet.duplicate() for packet in stream]
                    new_rtp_streams[new_stream_key] = new_stream
            
        self.rtp_streams = new_rtp_streams  # put new stream in


        new_stun_streams = {}

        for (stream_name,stream) in self.stun_streams.items():

            new_stun_streams[stream_name] = stream   # put original stream in

            for duplication_number in range(1, 1 + int(self.rules['ALL']['duplication_number'])):
                if int(self.rules['ALL']['duplicate_stream_chance']) >= get_rand_chance():
                    new_stream_key = (stream_name[0],duplication_number)
                    new_stream = [packet.duplicate() for packet in stream]
                    new_stun_streams[new_stream_key] = new_stream
            
        self.stun_streams = new_stun_streams  # put new stream in


        new_tls_streams = {}

        for (stream_name,stream) in self.tls_streams.items():

            new_tls_streams[stream_name] = stream   # put original stream in

            for duplication_number in range(1, 1 + int(self.rules['ALL']['duplication_number'])):
                if int(self.rules['ALL']['duplicate_stream_chance']) >= get_rand_chance():
                    new_stream_key = (stream_name[0],duplication_number)
                    new_stream = [packet.duplicate() for packet in stream]
                    new_tls_streams[new_stream_key] = new_stream
            
        self.tls_streams = new_tls_streams  # put new stream in


        new_dtls_streams = {}

        for (stream_name,stream) in self.dtls_streams.items():

            new_dtls_streams[stream_name] = stream   # put original stream in

            for duplication_number in range(1, 1 + int(self.rules['ALL']['duplication_number'])):
                if int(self.rules['ALL']['duplicate_stream_chance']) >= get_rand_chance():
                    new_stream_key = (stream_name[0],duplication_number)
                    new_stream = [packet.duplicate() for packet in stream]
                    new_dtls_streams[new_stream_key] = new_stream
            
        self.dtls_streams = new_dtls_streams  # put new stream in


        new_other_packets = {}

        for (stream_name,stream) in self.other_packets.items():

            new_other_packets[stream_name] = stream   # put original stream in

            for duplication_number in range(1, 1 + int(self.rules['ALL']['duplication_number'])):
                if int(self.rules['ALL']['duplicate_stream_chance']) >= get_rand_chance():
                    new_stream_key = (stream_name[0],duplication_number)
                    new_stream = [packet.duplicate() for packet in stream]
                    new_other_packets[new_stream_key] = new_stream
            
        self.other_packets = new_other_packets  # put new stream in


    def get_packets(self):
        ''' Returns all packets from all streams in one list. '''

        return [item for sublist in self.rtp_streams.values() for item in sublist]  + \
               [item for sublist in self.stun_streams.values() for item in sublist] + \
               [item for sublist in self.tls_streams.values() for item in sublist]  + \
               [item for sublist in self.dtls_streams.values() for item in sublist] + \
               [item for sublist in self.other_packets.values() for item in sublist]
            

    def print_streams(self):

        print("------------ S1_1 STREAMS -----------")
        for i,key in enumerate(self.rtp_streams):
            print("RTP_stream ",i+1,": ",self.basic_key[0],"|",self.basic_key[1],"|",self.basic_key[2],"|",self.basic_key[3],"|",key)
        for i,key in enumerate(self.stun_streams):
            print("STUN_stream ",i+1,": ",self.basic_key[0],"|",self.basic_key[1],"|",self.basic_key[2],"|",self.basic_key[3],"|",key)
        for i,key in enumerate(self.tls_streams):
            print("TLS_stream ",i+1,": ",self.basic_key[0],"|",self.basic_key[1],"|",self.basic_key[2],"|",self.basic_key[3],"|",key)
        for i,key in enumerate(self.dtls_streams):
            print("DTLS_stream ",i+1,": ",self.basic_key[0],"|",self.basic_key[1],"|",self.basic_key[2],"|",self.basic_key[3],"|",key)
        for i,key in enumerate(self.other_packets):
            print("Other_packets ",i+1,": ",self.basic_key[0],"|",self.basic_key[1],"|",self.basic_key[2],"|",self.basic_key[3],"|",key)
        print("------------------------------------")