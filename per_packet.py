
''' This file implements the per-packet processing. '''

from utility import *


def process_packets(packet_list, rules):
    ''' Process packets in the per-packet mode. The function goes through
        all packets in the list and randomizes them.
    '''

    packets_to_write = []

    # go through all packets in the pcap file
    for packet in packet_list:

        # do not randomize, remove or duplicate undefined packets
        if packet.config_section() == 'Undefined':
            packets_to_write.append(packet)
            continue

        # remove packet
        if int(rules[packet.config_section()]['delete_packet_chance']) >= get_rand_chance():
            continue

        # packet duplication version 1
        if int(rules[packet.config_section()]['duplication_version']) == 1:
            for _ in range(1, 1 + int(rules[packet.config_section()]['duplication_number'])):
                if int(rules[packet.config_section()]['duplicate_packet_chance']) >= get_rand_chance():
                    new_packet = packet.duplicate()
                    new_packet.randomize()
                    packets_to_write.append(new_packet)
            packet.randomize()
            packets_to_write.append(packet)

        # packet duplication version 2
        elif int(rules[packet.config_section()]['duplication_version']) == 2:
            packet.randomize()
            packets_to_write.append(packet)
            for _ in range(1, 1 + int(rules[packet.config_section()]['duplication_number'])):
                if int(rules[packet.config_section()]['duplicate_packet_chance']) >= get_rand_chance():
                    new_packet = packet.duplicate()
                    packets_to_write.append(new_packet)
        
    return packets_to_write # return a list of modified packets