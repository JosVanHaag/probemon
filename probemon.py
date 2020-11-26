#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging
from logging.handlers import RotatingFileHandler
from scapy.all import *
import argparse
import time
from datetime import datetime
import netaddr
import os
import sys
import paho.mqtt.client as mqtt
import json
import struct
import ifcfg
import re
from pid import PidFile
import traceback

NAME = 'probemon'
DESCRIPTION = "A command line tool for logging 802.11 probe request frames"
DEBUG = False

# logging.debug('This message should go to the log file')
# logging.info('So should this')
# logging.warning('And this, too')
# logging.error('And non-ASCII stuff, too, like Øresund and Malmö'


# ---------------------------------------------------------------------------------------
# Parsing the received signal strength indicator (RSSI) from radiotap header (borrowed from python-radiotap module)
# ---------------------------------------------------------------------------------------
def parse_rssi(packet):

    radiotap_header_fmt = '<BBHI'
    radiotap_header_len = struct.calcsize(radiotap_header_fmt)
    version, pad, radiotap_len, present = struct.unpack_from(radiotap_header_fmt, packet)

    start = radiotap_header_len

    bits = [int(b) for b in bin(present)[2:].rjust(32, '0')]
    bits.reverse()

    if bits[5] == 0:
        return 0

    while present & (1 << 31):
        present, = struct.unpack_from('<I', packet, start)
        start += 4

    offset = start

    if bits[0] == 1:
        offset = (offset + 8 - 1) & ~(8 - 1)
        offset += 8

    if bits[1] == 1:
        offset += 1

    if bits[2] == 1:
        offset += 1

    if bits[3] == 1:
        offset = (offset + 2 - 1) & ~(2 - 1)
        offset += 4

    if bits[4] == 1:
        offset += 2

    dbm_antsignal, = struct.unpack_from('<b', packet, offset)

    return dbm_antsignal

# ---------------------------------------------------------------------------------------
# Constructing the callback method for the sniffer
# ---------------------------------------------------------------------------------------
def build_packet_callback(oMqttClient, oOutputLogger, sDelimiter, bEmptySSID, mqtt_topic):

    def packetCallback(oPacket):

        # we are looking for management frames with a probe subtype
        # if neither match we are done here
        if oPacket.type != 0 or oPacket.subtype != 0x04 or oPacket.type is None:
            return

        # list of output fields
        aFields = []

        # Object of all output fields for MQTT-Broker
        aSensorData = {'macaddress': "", 'unixtime': "", 'isotime': "", 'vendor': "", 'ssid': "", 'rssi': 0}

        # Append time stamp in all beloved formats
        aFields.append(str(int(time.time())))
        aSensorData['isotime'] = datetime.now().isoformat()
        aFields.append(datetime.now().isoformat())
        aSensorData['unixtime'] = str(int(time.time()))

        # append the mac address itself
        aFields.append(oPacket.addr2)
        aSensorData['macaddress'] = oPacket.addr2

        # parse mac address and look up the organization from the vendor octets
        try:
            parsed_mac = netaddr.EUI(oPacket.addr2)
            sVendor = parsed_mac.oui.registration().org
        except netaddr.core.NotRegisteredError as e:
            sVendor = 'UNKNOWN'

        aFields.append(sVendor)
        aSensorData['vendor'] = sVendor

        # include the SSID in the probe frame
        sSSID = oPacket.info.decode(encoding='utf-8', errors='replace')
        #print(len(sSSID))

        if not bEmptySSID and len(sSSID) == 0:
            return

        aFields.append(sSSID)
        aSensorData['ssid'] = sSSID

        # include RSSI value
        sRssi = parse_rssi(memoryview(bytes(oPacket)))
        aFields.append(str(sRssi))
        aSensorData['rssi'] = sRssi

        # Join array with the chosen delimiter
        oOutputLogger.info(sDelimiter.join(aFields))

        # Push data to MQTT-Broker
        oMqttClient.publish(mqtt_topic, json.dumps(aSensorData), 1)

    return packetCallback


# ---------------------------------------------------------------------------------------
# Where the magic happens
# ---------------------------------------------------------------------------------------
def main():

    try:

        # Making sure the script is running only once
        with PidFile(NAME) as p:

            # oSyslogger.debug('this is debug')
            # oSyslogger.critical('this is critical')

            parser = argparse.ArgumentParser(description=DESCRIPTION)

            parser.add_argument('-i', '--interface',        default = 'mon0',               help = "capture interface")
            parser.add_argument('-b', '--max-bytes',        default = 5000000,              help = "maximum log size in bytes before rotating")
            parser.add_argument('-c', '--max-backups',      default = 99999,                help = "maximum number of log files to keep")
            parser.add_argument('-d', '--delimiter',        default = '\t',                 help = "output field delimiter")
            parser.add_argument('-D', '--debug',            action = 'store_true',          help = "enable debug output")
            parser.add_argument('-l', '--log',              action = 'store_true',          help = "enable scrolling live view of the logfile")
            parser.add_argument('-e', '--empty-ssid',       action = 'store_true',          help = "show requests with empty ssid's")
            parser.add_argument('-x', '--mqtt-broker',      default = '',                   help = "mqtt broker server")
            parser.add_argument('-o', '--mqtt-port',        default = '1883',               help = "mqtt broker port")
            parser.add_argument('-w', '--logfile',                                          help = "logging output location")
            parser.add_argument('-u', '--mqtt-user',        default = '',                   help = "mqtt user")
            parser.add_argument('-p', '--mqtt-password',    default = '',                   help = "mqtt password")
            parser.add_argument('-m', '--mqtt-topic',       default = 'probemon/request',   help = "mqtt topic")

            args = parser.parse_args()

            DEBUG = args.debug

            # Prepare Logging to /var/log/
            if not os.path.isdir('/var/log/' + NAME + '/'):
                os.mkdir('/var/log/' + NAME)

            oSyslogger = logging.getLogger(NAME)
            oSyslogger.setLevel(logging.DEBUG)
            oSyslogHandler = RotatingFileHandler('/var/log/' + NAME + '/error.log', maxBytes = 500000, backupCount = 10)
            oSyslogger.addHandler(oSyslogHandler)

            # Setup logger for event-logging
            oOutputLogger = logging.getLogger(NAME)
            oOutputLogger.setLevel(logging.INFO)

            # If logs should be written to console add handler for stdout
            if args.log:
                # oSyslogger.addHandler(logging.StreamHandler(sys.stdout))
                oOutputLogger.addHandler(logging.StreamHandler(sys.stdout))

            # If logfile should be written add handler for rotating logger
            if args.logfile:
                oHandler = RotatingFileHandler(args.logfile, maxBytes = int(args.max_bytes), backupCount = int(args.max_backups))
                oOutputLogger.addHandler(oHandler)

            oSyslogger.debug(NAME + " started in Debug-Mode")

            # Checking if interface existst and if not trying to establish under the name defined in command line args
            if not args.interface in ifcfg.interfaces().keys():
                oSyslogger.debug("Monitoring interface " + args.interface + " not present, trying to establish on wlan0 ...")
                # print("error: monitoring interface " + args.interface + " not present, trying to establish on wlan0...")
                oResult = os.popen("iw phy `iw dev wlan0 info | gawk '/wiphy/ {printf \"phy\" $2}'` interface add " + args.interface + " type monitor")
                sResult = oResult.read()
                # Quitting if interface could not be created
                if len(sResult) > 0:
                    print("ERROR: could not create " + args.interface)
                    sys.exit(-1)

            # Checking if interface is up
            oResult = os.popen('ifconfig')
            sResult = oResult.read()

            # Activating interface in case it's down
            if re.search(args.interface, sResult):
                # print("monitor mode active!")
                oSyslogger.debug("Monitor mode active.")
            else:
                print("monitor mode not active, activating now...")
                os.popen('ifconfig ' + args.interface + ' up')

                # Re-Check if monior mode has been activated
                oResult = os.popen('ifconfig')
                sResult = oResult.read()

                # Quit if monior mode could not be activated
                if re.search(args.interface, sResult):
                    print("Done!")
                else:
                    print("Error!")
                    sys.exit(-1)

            oMqttClient = mqtt.Client()

            # Initiate MQTT-Broker
            if args.mqtt_user and args.mqtt_password and args.mqtt_broker:
                oMqttClient.username_pw_set(args.mqtt_user, args.mqtt_password)
                oMqttClient.connect(args.mqtt_broker, int(args.mqtt_port), 1)
                oMqttClient.loop_start()

            # Build Callback for Sniffer
            oSniffPacket = build_packet_callback(oMqttClient, oOutputLogger, args.delimiter, args.empty_ssid, args.mqtt_topic)

            # Start Sniffer
            sniff(iface = args.interface, prn = oSniffPacket, store = 0, monitor = True)

    except Exception as e:

        sErrorName = type(e).__name__

        # PidFileAlreadyLockedError
        # PidFileAlreadyRunningError 
        # PidFileError

        if re.search("PidFile", sErrorName):
            print("ERROR: Already in use, can only run once")
        else:
            print(traceback.format_exc())


# ---------------------------------------------------------------------------------------
# The usual beauty of Python 
# ---------------------------------------------------------------------------------------
if __name__ == '__main__':
    main()