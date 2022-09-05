import configparser

'''
    Config file parser. This module is responsible for loading, parsing and creating config file.
'''

def warning_message(key, new_value, old_value):
    print("WARNING: " + str(key) + " value is unexpected (too big or small?). Value modified to " + str(new_value) + ". Previous value was " + str(old_value) + ".")

def check_min_max(config, section, key, min, max):
    ''' This function checks if value of a certain key in a certain subsection of a config file is within a specified interval. '''

    try:
        if int(config[section][key]) > max:
            warning_message(key, max, config[section][key])
            config[section][key] = str(max)
        elif int(config[section][key]) < min:
            warning_message(key, min, config[section][key])
            config[section][key] = str(min)
    except:
        print('ERROR: in ' + section + ', ' + key + ' cannot be converted to integer!')
        exit()

    return

def check_all(config):
    ''' This function takes a config dictionary and checks all keys in the ALL section.
        These keys have some constraints that have to be respected.
        If they do not respect them, warning message is printed and default
        value is assigned to the key. Default value for intervals is the closest
        number that is inside the interval.
    '''
    
    if config['ALL']['changeindividualpackets'] not in ['true', 'false']:
        warning_message('changeindividualpackets', 'false', config['ALL']['changeindividualpackets'])
        config['ALL']['changeindividualpackets'] = 'false'

    try:
        if int(config['ALL']['stream_processing_version']) not in [1,2,3]:
            warning_message('stream_processing_version', 1, config['ALL']['stream_processing_version'])
            config['ALL']['stream_processing_version'] = '1'
    except:
        print('ERROR: stream_processing_version cannot be converted to integer!')
        exit()
    
    check_min_max(config, 'ALL', 'delete_stream_chance', 0, 100)
    check_min_max(config, 'ALL', 'duplicate_stream_chance', 0, 100)

    try:
        if int(config['ALL']['duplication_number']) < 0:
            warning_message('duplication_number', 0, config['ALL']['duplication_number'])
            config['ALL']['duplication_number'] = '0'
    except:
        print('ERROR: duplication_number cannot be converted to integer!')
        exit()

    try:
        if int(config['ALL']['stream_duplication_version']) not in [1,2]:
            warning_message('stream_duplication_version', 1, config['ALL']['stream_duplication_version'])
            config['ALL']['stream_duplication_version'] = '1'
    except:
        print('ERROR: stream_duplication_version cannot be converted to integer!')
        exit()

    try:
        if int(config['ALL']['minimum_rtp_packets_in_stream']) < 0:
            warning_message('minimum_rtp_packets_in_stream', 0, config['ALL']['minimum_rtp_packets_in_stream'])
            config['ALL']['minimum_rtp_packets_in_stream'] = '0'
    except:
        print('ERROR: minimum_rtp_packets_in_stream cannot be converted to integer!')
        exit()

    return

def check_universal(config, section):
    ''' Similar function to check_all. This function checks common keys that all protocols share. '''

    check_min_max(config, section, 'delete_packet_chance', 0, 100)
    check_min_max(config, section, 'duplicate_packet_chance', 0, 100)

    try:
        if int(config[section]['duplication_number']) < 0:
            warning_message('duplication_number', 0, config[section]['duplication_number'])
            config[section]['duplication_number'] = '0'
    except:
        print('ERROR: in ' + section + ', duplication_number cannot be converted to integer!')
        exit()

    try:
        if int(config[section]['duplication_version']) not in [1,2]:
            warning_message('duplication_version', 1, config[section]['duplication_version'])
            config[section]['duplication_version'] = '1'
    except:
        print('ERROR: duplication_version cannot be converted to integer!')
        exit()

    check_min_max(config, section, 'source_ip_change_chance', 0, 100)
    check_min_max(config, section, 'destination_ip_change_chance', 0, 100)

    if config[section]['ipv4_randomize_parts'] not in ['network', 'host', 'both']:
        warning_message('ipv4_randomize_parts', 'both', config[section]['ipv4_randomize_parts'])
        config[section]['ipv4_randomize_parts'] = 'both'

    check_min_max(config, section, 'ipv4_mask_length', 0, 32)

    if config[section]['ipv6_randomize_parts'] not in ['network', 'host', 'both']:
        warning_message('ipv6_randomize_parts', 'both', config[section]['ipv6_randomize_parts'])
        config[section]['ipv6_randomize_parts'] = 'both'

    check_min_max(config, section, 'ipv6_mask_length', 0, 128)
    check_min_max(config, section, 'source_port_chance_change', 0, 100)
    check_min_max(config, section, 'destination_port_chance_change', 0, 100)
    check_min_max(config, section, 'source_port_min', 0, 65535)
    check_min_max(config, section, 'source_port_max', 0, 65535)
    check_min_max(config, section, 'destination_port_min', 0, 65535)
    check_min_max(config, section, 'destination_port_max', 0, 65535)
    check_min_max(config, section, 'time_chance_change', 0, 100)

    if config[section]['time_randomization_method'] not in ['normal', 'direct']:
        warning_message('time_randomization_method', 'direct', config[section]['time_randomization_method'])
        config[section]['time_randomization_method'] = 'direct'

    try:
        float(config[section]['time_constant'])
    except:
        print('ERROR: in ' + section + ', time_constant cannot be converted to float!')
        exit()

    return

def check_rtp(config):
    ''' Checks keys specific to RTP protocol. '''

    check_min_max(config, 'RTP', 'ssrc_chance_change', 0, 100)
    check_min_max(config, 'RTP', 'ssrc_min', 0, 4294967265)
    check_min_max(config, 'RTP', 'ssrc_max', 0, 4294967265)
    check_min_max(config, 'RTP', 'payload_type_chance_change', 0, 100)
    check_min_max(config, 'RTP', 'payload_type_min', 0, 127)
    check_min_max(config, 'RTP', 'payload_type_max', 0, 127)

    check_min_max(config, 'RTP', 'version_chance_change', 0, 100)
    check_min_max(config, 'RTP', 'version_min', 0, 3)
    check_min_max(config, 'RTP', 'version_max', 0, 3)
    check_min_max(config, 'RTP', 'padding_chance_change', 0, 100)
    check_min_max(config, 'RTP', 'padding_min', 0, 1)
    check_min_max(config, 'RTP', 'padding_max', 0, 1)
    check_min_max(config, 'RTP', 'extension_chance_change', 0, 100)
    check_min_max(config, 'RTP', 'extension_min', 0, 1)
    check_min_max(config, 'RTP', 'extension_max', 0, 1)
    check_min_max(config, 'RTP', 'csrc_count_chance_change', 0, 100)
    check_min_max(config, 'RTP', 'csrc_count_min', 0, 15)
    check_min_max(config, 'RTP', 'csrc_count_max', 0, 15)
    check_min_max(config, 'RTP', 'marker_chance_change', 0, 100)
    check_min_max(config, 'RTP', 'marker_min', 0, 1)
    check_min_max(config, 'RTP', 'marker_max', 0, 1)
    check_min_max(config, 'RTP', 'sequence_chance_change', 0, 100)
    check_min_max(config, 'RTP', 'sequence_min', 0, 65535)
    check_min_max(config, 'RTP', 'sequence_max', 0, 65535)
    check_min_max(config, 'RTP', 'timestamp_chance_change', 0, 100)
    check_min_max(config, 'RTP', 'timestamp_min', 0, 4294967295)
    check_min_max(config, 'RTP', 'timestamp_max', 0, 4294967295)

def check_rtcp(config):
    ''' Checks keys specific to RTCP protocol. '''

    check_min_max(config, 'RTCP', 'packet_type_chance_change', 0, 100)
    check_min_max(config, 'RTCP', 'packet_type_min', 0, 200)
    check_min_max(config, 'RTCP', 'packet_type_max', 0, 204)

    check_min_max(config, 'RTCP', 'version_chance_change', 0, 100)
    check_min_max(config, 'RTCP', 'version_min', 0, 3)
    check_min_max(config, 'RTCP', 'version_max', 0, 3)
    check_min_max(config, 'RTCP', 'padding_chance_change', 0, 100)
    check_min_max(config, 'RTCP', 'padding_min', 0, 1)
    check_min_max(config, 'RTCP', 'padding_max', 0, 1)
    check_min_max(config, 'RTCP', 'reception_report_count_chance_change', 0, 100)
    check_min_max(config, 'RTCP', 'reception_report_count_min', 0, 31)
    check_min_max(config, 'RTCP', 'reception_report_count_max', 0, 31)
    check_min_max(config, 'RTCP', 'length_chance_change', 0, 100)
    check_min_max(config, 'RTCP', 'length_min', 0, 65535)
    check_min_max(config, 'RTCP', 'length_max', 0, 65535)

def check_stun(config):
    ''' Checks keys specific to STUN protocol. '''

    check_min_max(config, 'STUN', 'transaction_id_chance_change', 0, 100)
    check_min_max(config, 'STUN', 'transaction_id_min', 0, 39614081257132168796771975167)
    check_min_max(config, 'STUN', 'transaction_id_max', 0, 39614081257132168796771975167)
    check_min_max(config, 'STUN', 'message_type_class_chance_change', 0, 100)
    check_min_max(config, 'STUN', 'message_type_class_min', 0, 3)
    check_min_max(config, 'STUN', 'message_type_class_max', 0, 3)

    check_min_max(config, 'STUN', 'first_chance_change', 0, 100)
    check_min_max(config, 'STUN', 'first_min', 0, 3)
    check_min_max(config, 'STUN', 'first_max', 0, 3)
    check_min_max(config, 'STUN', 'length_chance_change', 0, 100)
    check_min_max(config, 'STUN', 'length_min', 0, 65535)
    check_min_max(config, 'STUN', 'length_max', 0, 65535)
    check_min_max(config, 'STUN', 'cookie_chance_change', 0, 100)
    check_min_max(config, 'STUN', 'cookie_min', 0, 4294967295)
    check_min_max(config, 'STUN', 'cookie_max', 0, 4294967295)

def check_tls(config):
    ''' Checks keys specific to TLS protocol. '''

    check_min_max(config, 'TLS', 'content_type_chance_change', 0, 100)
    check_min_max(config, 'TLS', 'content_type_min', 0, 255)
    check_min_max(config, 'TLS', 'content_type_max', 0, 255)
    check_min_max(config, 'TLS', 'legacy_version_chance_change', 0, 100)
    check_min_max(config, 'TLS', 'legacy_version_min', 0, 65535)
    check_min_max(config, 'TLS', 'legacy_version_max', 0, 65535)
    check_min_max(config, 'TLS', 'length_chance_change', 0, 100)
    check_min_max(config, 'TLS', 'length_min', 0, 65535)
    check_min_max(config, 'TLS', 'length_max', 0, 65535)

    check_min_max(config, 'TLS', 'handshake_type_chance_change', 0, 100)
    check_min_max(config, 'TLS', 'handshake_type_min', 0, 255)
    check_min_max(config, 'TLS', 'handshake_type_max', 0, 255)
    check_min_max(config, 'TLS', 'hnd_length_chance_change', 0, 100)
    check_min_max(config, 'TLS', 'hnd_length_min', 0, 16777215)
    check_min_max(config, 'TLS', 'hnd_length_max', 0, 16777215)

def check_dtls(config):
    ''' Checks keys specific to DTLS protocol. '''

    check_min_max(config, 'DTLS', 'content_type_chance_change', 0, 100)
    check_min_max(config, 'DTLS', 'content_type_min', 0, 255)
    check_min_max(config, 'DTLS', 'content_type_max', 0, 255)
    check_min_max(config, 'DTLS', 'legacy_version_chance_change', 0, 100)
    check_min_max(config, 'DTLS', 'legacy_version_min', 0, 65535)
    check_min_max(config, 'DTLS', 'legacy_version_max', 0, 65535)
    check_min_max(config, 'DTLS', 'epoch_chance_change', 0, 100)
    check_min_max(config, 'DTLS', 'epoch_min', 0, 65535)
    check_min_max(config, 'DTLS', 'epoch_max', 0, 65535)
    check_min_max(config, 'DTLS', 'sequence_number_chance_change', 0, 100)
    check_min_max(config, 'DTLS', 'sequence_number_min', 0, 281474976710655)
    check_min_max(config, 'DTLS', 'sequence_number_max', 0, 281474976710655)
    check_min_max(config, 'DTLS', 'length_chance_change', 0, 100)
    check_min_max(config, 'DTLS', 'length_min', 0, 65535)
    check_min_max(config, 'DTLS', 'length_max', 0, 65535)

    check_min_max(config, 'DTLS', 'handshake_type_chance_change', 0, 100)
    check_min_max(config, 'DTLS', 'handshake_type_min', 0, 255)
    check_min_max(config, 'DTLS', 'handshake_type_max', 0, 255)
    check_min_max(config, 'DTLS', 'hnd_length_chance_change', 0, 100)
    check_min_max(config, 'DTLS', 'hnd_length_min', 0, 16777215)
    check_min_max(config, 'DTLS', 'hnd_length_max', 0, 16777215)
    check_min_max(config, 'DTLS', 'message_seq_chance_change', 0, 100)
    check_min_max(config, 'DTLS', 'message_seq_min', 0, 65535)
    check_min_max(config, 'DTLS', 'message_seq_max', 0, 65535)
    check_min_max(config, 'DTLS', 'fragment_offset_chance_change', 0, 100)
    check_min_max(config, 'DTLS', 'fragment_offset_min', 0, 16777215)
    check_min_max(config, 'DTLS', 'fragment_offset_max', 0, 16777215)
    check_min_max(config, 'DTLS', 'fragment_length_chance_change', 0, 100)
    check_min_max(config, 'DTLS', 'fragment_length_min', 0, 16777215)
    check_min_max(config, 'DTLS', 'fragment_length_max', 0, 16777215)

def parse_config_file(input_config_file):
    ''' This function reads and checks the config file. '''
    
    config = configparser.ConfigParser(allow_no_value=True)
    config.read(input_config_file)

    check_all(config) # check config options in the ALL section
    check_universal(config, 'RTP')
    check_rtp(config)
    check_universal(config, 'RTCP')
    check_rtcp(config)
    check_universal(config, 'STUN')
    check_stun(config)
    check_universal(config, 'TLS')
    check_tls(config)
    check_universal(config, 'DTLS')
    check_dtls(config)

    return {section:dict(config.items(section)) for section in config.sections()}

def generate_config_file(output_config_file):
    ''' This function is used to generate default config file. It can be used if a config file is broken. '''

    config = configparser.ConfigParser(allow_no_value=True)
    config['ALL'] = {
                     '# true -> change only individual packets, false -> change streams.': None,
                     'changeindividualpackets': 'false',
                     '# Versions: 1 -> basic, 2 -> advanced, 3 -> maximal.': None,
                     'stream_processing_version': '2',
                     '# Chance to delete stream in %, 100 means all will be deleted.': None,
                     'delete_stream_chance': '0',
                     '# Chance to duplicate stream in %, 100 means all will be duplicated.': None,
                     'duplicate_stream_chance': '0',
                     '# Maximum number of stream duplications.': None,
                     'duplication_number': '0',
                     '# Select stream duplication version described in documentation.': None,
                     'stream_duplication_version': '2',
                     '# Select the name of output file. You can also include absolute or relative path.': None,
                     'output_pcap_file': 'out.pcap',
                     '# Set minimum number of RTP packet suspects in a stream to consider them to be RTP packets.': None,
                     'minimum_rtp_packets_in_stream': '1',
                     }
    config['RTP'] = {
                     '# Chance that packet will be deleted, 0 -> no packet will be deleted.': None,
                     'delete_packet_chance': '0',
                     '# Chance that packet will be duplicated, 0 -> no packet will be duplicated.': None,
                     'duplicate_packet_chance': '0',
                     '# Maximum number of packet duplications.': None,
                     'duplication_number': '0',
                     '# Select packet duplication version described in documentation.': None,
                     'duplication_version': '2',
                     # individual field rules
                     '# Chance to change value in %, 100 means all will change.': None,
                     'source_ip_change_chance': '100',
                     'destination_ip_change_chance': '100',
                     '# Which part of the address should be randomized.': None,
                     '# Values: network | host | both.': None,
                     'ipv4_randomize_parts': 'both',
                     'ipv4_mask_length': '8',
                     'ipv6_randomize_parts': 'both',
                     'ipv6_mask_length': '16',
                     '# Chance to change port in %, 100 means all will change.': None,
                     'source_port_chance_change':'100',
                     'destination_port_chance_change':'100',
                     '# Select interval from which port values should be generated.': None,
                     'source_port_min': '1024',
                     'source_port_max': '65535',
                     'destination_port_min': '1024',
                     'destination_port_max': '65535',
                     '# Capture time randomization settings.': None,
                     'time_chance_change': '0',
                     '# time_randomization_method values: normal -> number generated from normal distribution, direct -> number inserted manually.': None,
                     'time_randomization_method': 'normal',
                     '# time_constant: standard deviation in case of normal distribution, number of seconds to be added or substracted.': None,
                     'time_constant': '0.5',
                     # RTP specific rules
                     '# SSRC randomization settings.': None,
                     'ssrc_chance_change': '100',
                     'ssrc_min': '0',
                     'ssrc_max': '4294967265',
                     '# Payload type randomization settings.': None,
                     'payload_type_chance_change': '0',
                     'payload_type_min': '0',
                     'payload_type_max': '127',
                     # ADDITIONAL OPTIONS
                     '# Version randomization settings.': None, # 2; 0-3
                     'version_chance_change': '0',
                     'version_min': '0',
                     'version_max': '3',
                     '# Padding randomization settings.': None, # 0; 0-1
                     'padding_chance_change': '0',
                     'padding_min': '0',
                     'padding_max': '1',
                     '# Extension randomization settings.': None, # 0; 0-1
                     'extension_chance_change': '0',
                     'extension_min': '0',
                     'extension_max': '1',
                     '# CSRC count randomization settings.': None, # 0; 0-15
                     'csrc_count_chance_change': '0',
                     'csrc_count_min': '0',
                     'csrc_count_max': '15',
                     '# Marker randomization settings.': None, # ?; 0-1
                     'marker_chance_change': '0',
                     'marker_min': '0',
                     'marker_max': '1',
                     '# Sequence number randomization settings.': None, # ?; 0-65535
                     'sequence_chance_change': '0',
                     'sequence_min': '0',
                     'sequence_max': '65535',
                     '# Timestamp randomization settings.': None, # ?; 0-4294967296
                     'timestamp_chance_change': '0',
                     'timestamp_min': '0',
                     'timestamp_max': '4294967295',
                     }
    config['RTCP'] = {
                     '# Chance that packet will be deleted, 0 -> no packet will be deleted.': None,
                     'delete_packet_chance': '0',
                     '# Chance that packet will be duplicated, 0 -> no packet will be duplicated.': None,
                     'duplicate_packet_chance': '0',
                     '# Maximum number of packet duplications.': None,
                     'duplication_number': '0',
                     '# Select packet duplication version described in documentation.': None,
                     'duplication_version': '2',
                     # individual field rules
                     '# Chance to change value in %, 100 means all will change.': None,
                     'source_ip_change_chance': '100',
                     'destination_ip_change_chance': '100',
                     '# Which part of the address should be randomized.': None,
                     '# Values: network | host | both.': None,
                     'ipv4_randomize_parts': 'both',
                     'ipv4_mask_length': '8',
                     'ipv6_randomize_parts': 'both',
                     'ipv6_mask_length': '16',
                     '# Chance to change port in %, 100 means all will change.': None,
                     'source_port_chance_change':'100',
                     'destination_port_chance_change':'100',
                     '# Select interval from which port values should be generated.': None,
                     'source_port_min': '1024',
                     'source_port_max': '65535',
                     'destination_port_min': '1024',
                     'destination_port_max': '65535',
                     '# Capture time randomization settings.': None,
                     'time_chance_change': '0',
                     '# time_randomization_method values: normal -> number generated from normal distribution, direct -> number inserted manually.': None,
                     'time_randomization_method': 'normal',
                     '# time_constant: standard deviation in case of normal distribution, number of seconds to be added or substracted.': None,
                     'time_constant': '0.5',
                     # RTCP specific rules
                     '# SSRC randomization settings are the same as RTP SSRC settings (both are connected).': None,
                     '# Packet type randomization settings.': None,
                     'packet_type_chance_change': '0',
                     'packet_type_min': '200',
                     'packet_type_max': '204',
                     # ADDITIONAL OPTIONS
                     '# Version randomization settings.': None, # 2; 0-3
                     'version_chance_change': '0',
                     'version_min': '0',
                     'version_max': '3',
                     '# Padding randomization settings.': None, # 0; 0-1
                     'padding_chance_change': '0',
                     'padding_min': '0',
                     'padding_max': '1',
                     '# Reception report count randomization settings.': None, # 0; 0-32
                     'reception_report_count_chance_change': '0',
                     'reception_report_count_min': '0',
                     'reception_report_count_max': '31',
                     '# Length randomization settings.': None, # ?; 0-65536
                     'length_chance_change': '0',
                     'length_min': '0',
                     'length_max': '65535',
                     }
    config['STUN'] = {
                     '# Chance that packet will be deleted, 0 -> no packet will be deleted.': None,
                     'delete_packet_chance': '0',
                     '# Chance that packet will be duplicated, 0 -> no packet will be duplicated.': None,
                     'duplicate_packet_chance': '0',
                     '# Maximum number of packet duplications.': None,
                     'duplication_number': '0',
                     '# Select packet duplication version described in documentation.': None,
                     'duplication_version': '2',
                     # individual field rules
                     '# Chance to change value in %, 100 means all will change.': None,
                     'source_ip_change_chance': '100',
                     'destination_ip_change_chance': '100',
                     '# Which part of the address should be randomized.': None,
                     '# Values: network | host | both.': None,
                     'ipv4_randomize_parts': 'both',
                     'ipv4_mask_length': '8',
                     'ipv6_randomize_parts': 'both',
                     'ipv6_mask_length': '16',
                     '# Chance to change port in %, 100 means all will change.': None,
                     'source_port_chance_change':'100',
                     'destination_port_chance_change':'100',
                     '# Select interval from which port values should be generated.': None,
                     'source_port_min': '1024',
                     'source_port_max': '65535',
                     'destination_port_min': '1024',
                     'destination_port_max': '65535',
                     '# Capture time randomization settings.': None,
                     'time_chance_change': '0',
                     '# time_randomization_method values: normal -> number generated from normal distribution, direct -> number inserted manually.': None,
                     'time_randomization_method': 'normal',
                     '# time_constant: standard deviation in case of normal distribution, number of seconds to be added or substracted.': None,
                     'time_constant': '0.5',
                     # STUN specific rules
                     '# Transaction id randomization settings.': None,
                     'transaction_id_chance_change': '0',
                     'transaction_id_min': '0',
                     'transaction_id_max': '39614081257132168796771975167',
                     '# Message type class randomization settings.': None,
                     'message_type_class_chance_change': '0',
                     'message_type_class_min': '0',
                     'message_type_class_max': '3',
                     # ADDITIONAL OPTIONS
                     '# First two bits randomization settings.': None, # 2; 0-3
                     'first_chance_change': '0',
                     'first_min': '0',
                     'first_max': '3',
                     '# Length randomization settings.': None, # ?; 0-65536
                     'length_chance_change': '0',
                     'length_min': '0',
                     'length_max': '65535',
                     '# Magic cookie randomization settings.': None, # ?; 0-4294967296
                     'cookie_chance_change': '0',
                     'cookie_min': '0',
                     'cookie_max': '4294967295',
                     }
    config['TLS'] = {
                     '# Chance that packet will be deleted, 0 -> no packet will be deleted.': None,
                     'delete_packet_chance': '0',
                     '# Chance that packet will be duplicated, 0 -> no packet will be duplicated.': None,
                     'duplicate_packet_chance': '0',
                     '# Maximum number of packet duplications.': None,
                     'duplication_number': '0',
                     '# Select packet duplication version described in documentation.': None,
                     'duplication_version': '2',
                     # individual field rules
                     '# Chance to change value in %, 100 means all will change.': None,
                     'source_ip_change_chance': '100',
                     'destination_ip_change_chance': '100',
                     '# Which part of the address should be randomized.': None,
                     '# Values: network | host | both.': None,
                     'ipv4_randomize_parts': 'both',
                     'ipv4_mask_length': '8',
                     'ipv6_randomize_parts': 'both',
                     'ipv6_mask_length': '16',
                     '# Chance to change port in %, 100 means all will change.': None,
                     'source_port_chance_change':'100',
                     'destination_port_chance_change':'100',
                     '# Select interval from which port values should be generated.': None,
                     'source_port_min': '1024',
                     'source_port_max': '65535',
                     'destination_port_min': '1024',
                     'destination_port_max': '65535',
                     '# Capture time randomization settings.': None,
                     'time_chance_change': '0',
                     '# time_randomization_method values: normal -> number generated from normal distribution, direct -> number inserted manually.': None,
                     'time_randomization_method': 'normal',
                     '# time_constant: standard deviation in case of normal distribution, number of seconds to be added or substracted.': None,
                     'time_constant': '0.5',
                     # TLS specific rules
                     # ADDITIONAL OPTIONS
                     '# Content type randomization settings.': None, # 2; 0-256
                     'content_type_chance_change': '0',
                     'content_type_min': '0',
                     'content_type_max': '255',
                     '# Legacy version randomization settings.': None, # ?; 0-65536
                     'legacy_version_chance_change': '0',
                     'legacy_version_min': '0',
                     'legacy_version_max': '65535',
                     '# Length randomization settings.': None, # ?; 0-65536
                     'length_chance_change': '0',
                     'length_min': '0',
                     'length_max': '65535',
                     # ADDITIONAL HANDSHAKE OPTIONS
                     '# Handshake type randomization settings.': None, # 2; 0-256
                     'handshake_type_chance_change': '0',
                     'handshake_type_min': '0',
                     'handshake_type_max': '255',
                     '# Handshake length randomization settings.': None, # ?; 0-16777216
                     'hnd_length_chance_change': '0',
                     'hnd_length_min': '0',
                     'hnd_length_max': '16777215',
                     }
    config['DTLS'] = {
                     '# chance that packet will be deleted, 0 -> no packet will be deleted': None,
                     'delete_packet_chance': '0',
                     '# Chance that packet will be duplicated, 0 -> no packet will be duplicated.': None,
                     'duplicate_packet_chance': '0',
                     '# Maximum number of packet duplications.': None,
                     'duplication_number': '0',
                     '# Select packet duplication version described in documentation.': None,
                     'duplication_version': '2',
                     # individual field rules
                     '# Chance to change value in %, 100 means all will change.': None,
                     'source_ip_change_chance': '100',
                     'destination_ip_change_chance': '100',
                     '# Which part of the address should be randomized.': None,
                     '# Values: network | host | both.': None,
                     'ipv4_randomize_parts': 'both',
                     'ipv4_mask_length': '8',
                     'ipv6_randomize_parts': 'both',
                     'ipv6_mask_length': '16',
                     '# Chance to change port in %, 100 means all will change.': None,
                     'source_port_chance_change':'100',
                     'destination_port_chance_change':'100',
                     '# Select interval from which port values should be generated.': None,
                     'source_port_min': '1024',
                     'source_port_max': '65535',
                     'destination_port_min': '1024',
                     'destination_port_max': '65535',
                     '# Capture time randomization settings.': None,
                     'time_chance_change': '0',
                     '# time_randomization_method values: normal -> number generated from normal distribution, direct -> number inserted manually.': None,
                     'time_randomization_method': 'normal',
                     '# time_constant: standard deviation in case of normal distribution, number of seconds to be added or substracted.': None,
                     'time_constant': '0.5',
                     # TLS specific rules
                     # ADDITIONAL OPTIONS
                     '# Content type randomization settings.': None, # 2; 0-256
                     'content_type_chance_change': '0',
                     'content_type_min': '0',
                     'content_type_max': '255',
                     '# Legacy version randomization settings.': None, # ?; 0-65536
                     'legacy_version_chance_change': '0',
                     'legacy_version_min': '0',
                     'legacy_version_max': '65535',
                     '# Epoch randomization settings.': None, # ?; 0-65536
                     'epoch_chance_change': '0',
                     'epoch_min': '0',
                     'epoch_max': '65535',
                     '# Sequence number randomization settings.': None, # ?; 0-281474976710656
                     'sequence_number_chance_change': '0',
                     'sequence_number_min': '0',
                     'sequence_number_max': '281474976710655',
                     '# Length randomization settings.': None, # ?; 0-65536
                     'length_chance_change': '0',
                     'length_min': '0',
                     'length_max': '65535',
                     # ADDITIONAL HANDSHAKE OPTIONS
                     '# Handshake type randomization settings.': None, # 2; 0-256
                     'handshake_type_chance_change': '0',
                     'handshake_type_min': '0',
                     'handshake_type_max': '255',
                     '# Handshake length randomization settings.': None, # ?; 0-16777216
                     'hnd_length_chance_change': '0',
                     'hnd_length_min': '0',
                     'hnd_length_max': '16777215',
                     '# Message seq randomization settings.': None, # ?; 0-65536
                     'message_seq_chance_change': '0',
                     'message_seq_min': '0',
                     'message_seq_max': '65535',
                     '# Fragment offset randomization settings.': None, # ?; 0-16777216
                     'fragment_offset_chance_change': '0',
                     'fragment_offset_min': '0',
                     'fragment_offset_max': '16777215',
                     '# Fragment length randomization settings.': None, # ?; 0-16777216
                     'fragment_length_chance_change': '0',
                     'fragment_length_min': '0',
                     'fragment_length_max': '16777215',
                     }
    
    with open(output_config_file, 'w') as configfile:
        config.write(configfile)
