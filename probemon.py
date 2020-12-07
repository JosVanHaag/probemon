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
DESCRIPTION = "A command line tool for logging and MQTT'ing 802.11 probe request frames"
DEBUG = False
VERSION = "1.0.14"

# ---------------------------------------------------------------------------------------
# Pre-arranging all the needed stuff and starting the sniffer routine
# ---------------------------------------------------------------------------------------
def main():

    try:

        # Making sure the script is running only once
        with PidFile(NAME) as p:

            sIgnoreListPath = os.path.dirname(__file__) + "/ignore.list"

            oParser = argparse.ArgumentParser(description = DESCRIPTION)

            oParser.add_argument('-i', '--interface',        default = 'mon0',               help = "capture interface")
            oParser.add_argument('-b', '--max-bytes',        default = 5000000,              help = "maximum log size in bytes before rotating")
            oParser.add_argument('-c', '--max-backups',      default = 99999,                help = "maximum number of log files to keep")
            oParser.add_argument('-d', '--delimiter',        default = '\t',                 help = "output field delimiter")
            oParser.add_argument('-D', '--debug',            action = 'store_true',          help = "enable debug output")
            oParser.add_argument('-l', '--log',              action = 'store_true',          help = "enable scrolling live view of the logfile")
            oParser.add_argument('-I', '--ignore',           default = sIgnoreListPath,      help = "path to list of probe requests that can be ignored")
            oParser.add_argument('-e', '--empty-ssid',       action = 'store_true',          help = "show requests with empty ssid's")
            oParser.add_argument('-x', '--mqtt-broker',      default = '',                   help = "mqtt broker server")
            oParser.add_argument('-o', '--mqtt-port',        default = '1883',               help = "mqtt broker port")
            oParser.add_argument('-w', '--logfile',                                          help = "logging output location")
            oParser.add_argument('-u', '--mqtt-user',        default = '',                   help = "mqtt user")
            oParser.add_argument('-p', '--mqtt-password',    default = '',                   help = "mqtt password")
            oParser.add_argument('-m', '--mqtt-topic',       default = 'probemon/request',   help = "mqtt topic")

            oArgs = oParser.parse_args()

            DEBUG = oArgs.debug

            print(type(oArgs))

            # Prepare Logging to /var/log/
            if not os.path.isdir('/var/log/' + NAME + '/'):
                os.mkdir('/var/log/' + NAME)

            #Setup logger for err/debug logging
            oSyslogger = logging.getLogger(NAME + "_err")
            oSyslogger.setLevel(logging.DEBUG)
            oSyslogHandler = RotatingFileHandler('/var/log/' + NAME + '/error.log', maxBytes = 500000, backupCount = 10)
            oSyslogger.addHandler(oSyslogHandler)

            # Setup logger for event-logging
            oOutputLogger = logging.getLogger(NAME + "_event")
            oOutputLogger.setLevel(logging.INFO)

            # If logs should be written to console add handler for stdout
            if oArgs.log:
                oSyslogger.addHandler(logging.StreamHandler(sys.stdout))
                oOutputLogger.addHandler(logging.StreamHandler(sys.stdout))

            # If logfile should be written add handler for rotating logger
            if oArgs.logfile:
                oHandler = RotatingFileHandler(oArgs.logfile, maxBytes = int(oArgs.max_bytes), backupCount = int(oArgs.max_backups))
                oOutputLogger.addHandler(oHandler)

            oSyslogger.debug(datetime.now().isoformat() + "\t" + NAME.capitalize() + " (" + VERSION + ") started in debug mode")

            # Checking if interface existst and if not trying to establish under the name defined in command line args
            if not oArgs.interface in ifcfg.interfaces().keys():
                oSyslogger.debug(datetime.now().isoformat() + "\tMonitoring interface " + oArgs.interface + " not present, trying to establish on wlan0 ...")
                oResult = os.popen("iw phy `iw dev wlan0 info | gawk '/wiphy/ {printf \"phy\" $2}'` interface add " + oArgs.interface + " type monitor")
                sResult = oResult.read()
                # Quitting if interface could not be created
                if len(sResult) > 0:
                    oSyslogger.error(datetime.now().isoformat() + "\tCould not create " + oArgs.interface + "\nExit")
                    sys.exit(-1)
                else:
                    oSyslogger.debug(datetime.now().isoformat() + "\tMonitoring interface " + oArgs.interface + " successfully added")

            # Checking if interface is up
            oResult = os.popen('ifconfig')
            sResult = oResult.read()

            # Activating interface in case it's down
            if re.search(oArgs.interface, sResult):
                oSyslogger.debug(datetime.now().isoformat() + "\tMonitor mode is active at " + oArgs.interface)
            else:
                oSyslogger.debug(datetime.now().isoformat() + "\tMonitor mode is not active, trying to activate...")
                os.popen('ifconfig ' + oArgs.interface + ' up')

                # Re-Check if monior mode has been activated
                oResult = os.popen('ifconfig')
                sResult = oResult.read()

                # Quit if monitor mode could not be activated
                if re.search(oArgs.interface, sResult):
                    oSyslogger.debug(datetime.now().isoformat() + "\tMonitor mode successfully activated at " + oArgs.interface)
                else:
                    oSyslogger.error(datetime.now().isoformat() + "\tCould not activate monitor mode at " + oArgs.interface + "\nExit")
                    sys.exit(-1)

            oMqttClient = mqtt.Client()

            # Initiate MQTT-Broker
            if oArgs.mqtt_broker:
                oSyslogger.debug(datetime.now().isoformat() + "\tInitiating MQTT broker")
                # If username and password are provided, use them.
                if oArgs.mqtt_user and oArgs.mqtt_password:
                     oMqttClient.username_pw_set(oArgs.mqtt_user, oArgs.mqtt_password)
                oMqttClient.connect(oArgs.mqtt_broker, int(oArgs.mqtt_port), 1)
                oMqttClient.loop_start()

            # Loading ignore-list, if available
            oSyslogger.debug(datetime.now().isoformat() + "\tLooking for ignore list")
            aIgnore = []
            if os.path.isfile(oArgs.ignore):
                f = open(oArgs.ignore, "r")
                for sLine in f.read().splitlines():
                    if len(sLine.strip()) > 0 and not sLine.strip()[0] == "#":
                        aIgnore.append(sLine.strip())

            if len(aIgnore) == 0:
                oSyslogger.debug(datetime.now().isoformat() + "\tNothing to ignore")
            else:
                oSyslogger.debug(datetime.now().isoformat() + "\tFound ignores: " + "; ".join(aIgnore))

            # Build Callback for Sniffer
            oSyslogger.debug(datetime.now().isoformat() + "\tBuilding packet for sniffer")
            oSniffPacket = build_packet_callback(oMqttClient, oOutputLogger, oSyslogger, oArgs.delimiter, oArgs.empty_ssid, oArgs.mqtt_topic, aIgnore)

            # Start Sniffer
            oSyslogger.debug(datetime.now().isoformat() + "\tStarting sniffer, awaiting probe requests...")
            sniff(iface = oArgs.interface, prn = oSniffPacket, store = 0, monitor = True)

            

    except KeyboardInterrupt:
        oSyslogger.error(datetime.now().isoformat() + "\tGracefull exit by keyboard interrupt")
        sys.exit()

    except Exception as e:

        sErrorName = type(e).__name__

        # PidFileAlreadyLockedError
        # PidFileAlreadyRunningError 
        # PidFileError

        if re.search("PidFile", sErrorName):
            oSyslogger.error(datetime.now().isoformat() + "\tAn instance of this script ist already running\nExit")
        else:
            oSyslogger.error(datetime.now().isoformat() + "\tAn error occured in <main>:\n" + traceback.format_exc())


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
def build_packet_callback(oMqttClient, oOutputLogger, oSyslogger, sDelimiter, bEmptySSID, mqtt_topic, aIgnore):

    def packetCallback(oPacket):

        try:

            # Check, if packet has attributes and the attributes match probe request
            if not hasattr(oPacket, 'type') or not hasattr(oPacket, 'subtype'):
                return
            if oPacket.type != 0 or oPacket.subtype != 0x04 or oPacket.type is None:
                return

            # list of output fields
            aFields = []

            # Object of all output fields for MQTT-Broker
            aSensorData = {'macaddress': "", 'unixtime': "", 'isotime': "", 'vendor': "", 'ssid': "", 'rssi': 0}

            # Append time stamp in all beloved formats
            aFields.append(datetime.now().isoformat())
            aSensorData['isotime'] = datetime.now().isoformat()
            aFields.append(str(int(time.time())))
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


            sAllFields = sDelimiter.join(aFields)
            for sRegex in aIgnore:
                if re.search(sRegex, sAllFields):
                    return

            # Join array with the chosen delimiter
            oOutputLogger.info(sDelimiter.join(aFields))

            # Push data to MQTT-Broker
            oMqttClient.publish(mqtt_topic, json.dumps(aSensorData), 1)

        except Exception as e:

            sErrorName = type(e).__name__
            oSyslogger.error(datetime.now().isoformat() + "\tAn error occured in <packetCallback> (" + sErrorName + ")\n" + traceback.format_exc())


    return packetCallback


# ---------------------------------------------------------------------------------------
# The usual beauty of Python 
# ---------------------------------------------------------------------------------------
if __name__ == '__main__':
    main()