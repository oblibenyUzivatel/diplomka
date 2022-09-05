#!/usr/bin/env python

'''
    Main file of this script. Controls computation flow.
'''

# import python modules
from xmlrpc.client import Boolean
from scapy.all import *
import sys
from per_packet import process_packets

# import other files
from packet_classification import *
from utility import *
from config_parser import *
from packet_classes import *
from RTP_streams import RTP_Streams


def print_help():
    print("Run this script like this:\n",
        "\t1) python diplomka.py <filename.pcap> [config_file]\t--> Randomize pcap file.\n",
        "\t2) python diplomka.py -g [config_file]\t\t\t--> Generate default config file.")

def parse_packets():
    '''
        Main function of this program. Loads everything, then runs packet classification,
        then randomizes packets and finally sorts and writes packets to pcap file.
    '''
    
    # PARSE FILE NAME FROM ARGUMENTS
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print_help()
        return False

    if sys.argv[1] == '-g': # generate config file option
        if len(sys.argv) == 3: # get optional name of generated config file
            output_config_file = sys.argv[2]
        else:
            output_config_file = 'config.ini'
        try:
            generate_config_file(output_config_file)
        except:
            print("Could not generate config file: " + output_config_file)
        exit()

    pcap_file = sys.argv[1] # get the name of pcap file
    if len(sys.argv) == 3:  # get optional name of input config file
        input_config_file = sys.argv[2]
    else:
        input_config_file = 'config.ini'

    # LOAD PACKETS FROM PCAP FILE
    try:
        capture = rdpcap(pcap_file)
    except:
        print("Could not load pcap file: " + pcap_file)
        exit()

    # LOAD CONFIGURATION SETTINGS FROM FILE
    #generate_config_file('config.ini') # remove later
    try:
        rules = parse_config_file(input_config_file)
    except:
        print("Could not load config file.")
        exit()

    # PACKET CLASSIFICATION ------------------------------------------
    if rules['ALL']['changeindividualpackets'] == "true":
        packets_to_write = classification_function(capture, True, rules)
    else:
        (packets_to_write, streams) = classification_function(capture, False, rules)

    # PACKET RANDOMIZATION ---------------------------------------------------------
    if rules['ALL']['changeindividualpackets'] == "true":
        packets_to_write = process_packets(packets_to_write, rules)
    else:
        streams.process_streams()
        packets_to_write = packets_to_write + streams.get_packets()

    # WRITE PACKETS TO OUTPUT PCAP FILE
    packets_to_write = [p.packet_to_write() for p in packets_to_write]
    packets_to_write.sort(key=lambda a: a.time)
    wrpcap(rules['ALL']['output_pcap_file'], packets_to_write)
    
    
parse_packets()
