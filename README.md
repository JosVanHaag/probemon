# probemon

A simple command line tool for monitoring and logging 802.11 probe requests. The requests are output live and/or written to a log file and/or forwarded to an MQTT broker.

||||
|--|--|--|
|-i|-\-interface| defaults to mon0
|-b|-\-max-bytes| maximum log size in bytes before rotating|
|-c|-\-max-backups| maximum number of log files to keep|
|-d|-\-delimiter| output field delimiter|
|-s|-\-ssid| include probe SSID in output|
|-r|-\-rssi| include rssi in output|
|-D|-\-debug| enable debug output|
|-l|-\-log| enable scrolling live view of the logfile|
|-x|-\-mqtt-broker| mqtt broker server|
|-o|-\-mqtt-port| mqtt broker port|
|-w|-\-logfile| logging output location|
|-u|-\-mqtt-user| mqtt user|
|-p|-\-mqtt-password| mqtt password|
|-m|-\-mqtt-topic| mqtt topic|
|-I|-\-ignore| path to list of probe requests that can be ignored|
|-e|-\-empty-ssid| show requests with empty ssid's|
