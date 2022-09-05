
''' This file implements the classification part of this program. '''

from decoder import Decoder
from RTP_streams import RTP_Streams
from s3 import *
from s2 import *
from s1 import *


def classification_function(capture, per_packet, rules):
    ''' Function goes through all captured packets and tries to classify them. '''

    # INFO - REMOVE LATER
    rtp_count = 0
    rtcp_count = 0
    stun_count = 0
    tls_count = 0
    dtls_count = 0
    other_count = 0

    # list of packets to write
    packets_to_write = []
    # create RTP streams container
    rtp_streams = RTP_Streams(rules)

    # choose stream processing version
    if int(rules['ALL']['stream_processing_version']) == 1:
        streams = S1(rules)
    elif int(rules['ALL']['stream_processing_version']) == 2:
        streams = S2(rules)
    elif int(rules['ALL']['stream_processing_version']) == 3:
        streams = S3(rules)
    else:
        print("Wrong stream processing version choice!")
        exit()

    for packet in capture:
        
        if Decoder.isRTPpacket(packet):
            rtp_count = rtp_count + 1 # debug

            if per_packet == True:  # per-packet processing
                rtp_streams.add((True, MyPacket(packet, rules)))
            else:                   # per-stream processing
                rtp_streams.add((True, MyPacket(packet, rules)))

        elif Decoder.isRTCPpacket(packet):
            rtcp_count = rtcp_count + 1

            if per_packet == True:  # per-packet processing
                rtp_streams.add((False, MyPacket(packet, rules)))
            else:                   # per-stream processing
                rtp_streams.add((False, MyPacket(packet, rules)))

        elif Decoder.isSTUNpacket(packet):
            stun_count = stun_count + 1

            stun_packet = STUN_packet(packet, rules)

            if per_packet == True:  # per-packet processing
                packets_to_write.append(stun_packet)
            else:                   # per-stream processing
                streams.add(stun_packet)

        elif Decoder.isTLSpacket(packet):
            tls_count = tls_count + 1

            tls_packet = TLS_packet(packet, rules)

            if per_packet == True:  # per-packet processing
                packets_to_write.append(tls_packet)
            else:                   # per-stream processing
                streams.add(tls_packet)

        elif Decoder.isDTLSpacket(packet):
            dtls_count = dtls_count + 1

            dtls_packet = DTLS_packet(packet, rules)

            if per_packet == True:  # per-packet processing
                packets_to_write.append(dtls_packet)
            else:                   # per-stream processing
                streams.add(dtls_packet)

        else:
            other_count = other_count + 1

            other_packet = MyPacket(packet, rules)

            if per_packet == True:  # per-packet processing
                packets_to_write.append(other_packet)
            else:                   # per-stream processing
                packets_to_write.append(other_packet)

    # ADVANCED RTP CHECK
    removed_streams = rtp_streams.stream_check()
    for (_,packets) in rtp_streams:
        for (is_rtp, packet) in packets:
            if is_rtp:
                p = RTP_packet(packet.packet, rules)
            else:
                p = RTCP_packet(packet.packet, rules)
            if per_packet == True:  # per-packet processing
                packets_to_write.append(p)
            else:                   # per-stream processing
                streams.add(p)
    
    for (_,packets) in removed_streams.items():
        for (_,packet) in packets:
            if per_packet == True:  # per-packet processing
                packets_to_write.append(packet)
            else:                   # per-stream processing
                streams.add(packet)

    if per_packet == True:  # per-packet processing
        return packets_to_write
    else:                   # per-stream processing
        return (packets_to_write, streams)