# Network-Based Attacks

Network attacks relays on network organization, network traffic and network protocols as:

- ARP
- DHCP
- SMB
- FTP
- Telnet
- SSH

## Filtering traffic with wireshark

The view tab lets the user to add more columns, with that src and dest ports can be added to the datagram.

There are different layers when inspecting the packets:

- Headers (Frame section): The header section it´s located with the frame data it contains info like the length in bytes of the packet, the interface were the packet was captured, and the id of the packet.
- Network layer (Ethernet II): The network section contains information such as the source and destination hostnames/domains and the actual dest and src MAC adresses.
- IP layer (Internet Protocol Version 4): It contains the information about the source and destination IPv4
- TCP layer (Transmission Control Protocol): Contains the information about the source and destination ports and the flags set for the packet.
- HTTP layer or Application layer: Contains the actual body data of the packet, in case of HTTP the method and data transmited.

For exporting captured artefacts from the TCP/HTTP/Other streams it can be done by `File > Export Objects > HTTP `

## Tshark

`Tshark` it a tools used to analyze pcap files and its packets via CLI, its very similar to tcpdump.

- `tshark -r <pcap_capture>` will show the content of the capture
- `tshark -r <pcap_capture> | wc -l` will count the amount of lines which is the same as the total packets count
- `tshark -r <pcap_capture> -z io,phs -q` will show the statistics of the Protocol Hierarchy Statistics (PHS)
- `tshark -r <pcap_capture> -c <packet_count>` will only show the first n packets
- `tshark -r <pcap_capture> -Y '<protocol>' | more` will show specific protocol traffic
- `tshark -r <pcap_capture> -Y 'ip.src==<src_ip> && ip.dst==<dst_ip>'` will show the traffic from src ip to dst ip
- `tshark -r <pcap_capture> -Y 'http.request.method==<method>' | more` will show the requests that matches the specified method
- `tshark -r <pcap_capture> -Y 'http.request.method==<method>' -Tfields -e frame.time -e ip.src -e http.request.full_uri | more` will show the request that matches the specified method, the fields that will show are the time, the src ip and the requested URL
- `tshark -r <pcap_capture> -Y 'http contains <search_string>'` will search for the specified string
- `tshark -r <pcap_capture> -Y 'http.request.method==<method> && http.host==<host_url>' -Tfields -e ip.dst` will show the mathed dst ip
- `tshark -r <pcap_capture> -Y 'ip contains <search_string> && ip.src=<src_ip>' -Tfields -e ip.src -e http.cookie` will show the src ip and the aggregated cookie for the specified matched string
- `tshark -r <pcap_capture> -Y 'ip.src==<ip> && http'` 
- `Tfields -e http.user_agent` will show the src ip and the used user agent

## ARP Poisoning

For ARP poisoning its important to get the MAC addresses of the target net, `wireshark` can be used for it.
Then for ARP spoofing the tool `arpspoof` can be used by executing:
- `echo 1> /proc/sys/net/ipv4/ip_forward`
- `arpspoof -i <interface> -t <target_ip> -r <host>`

## WiFi Traffic analysis

WireShark filters:

- `wlan contains <SSID>` will search for the traffic inside specified SSID network, then inside the packets at hte IEEE section the transmitter MAC address can be found. At the `IEEE 802.11 Wireless LAN` section inside a packet it can be found the encryption algorithm that is associated with the security of the network.
- `(wlan.fc.type_subtype == 0x0008) && (!(wlan.wfa.ie.wpa.version == 1)) && !(wlan.tag.number == 48)` will search for open wifi networks
-  `(wlan.ta == <MAC addr>) || (wlan.ra == <MAC addr>)` will display the packets received and transmitted20
-  on a device
- `wlan contains <ssid> && wlan.fc.type_subtype == 8` will locate the traffic packets with WPS, to see if WPS was enabled it can be checked by looking up `tag vendor specific WPS` inside the packet.
- `((wlan.addr == <rooter MAC address>)) && ((wlan.fc.type_subtype == 0x0020))` will look for traffic containing data conatining the specified MAC address
- `((wlan.bssid == <destination MAC address>)) && ((wlan.addr == <rooter MAC address>)) && ((wlan.fc.type_subtype == 0x0001))` will search for association request packets

## Filtering WiFi

- `tshark -r <capture> -Y 'wlan.fc.type_subtype==0x000c'` will siplay deauth packets
- `tshark -r <capture> -Y 'eapol'` will display the handshake packets
- `tshark -r <capture> -Y 'wlan.fc.type.subtype==8' -Tfields -e wlan.ssid -e wlan.bssid` will display ssid and bssid of the devices that connected to the open network
- `tshark -r <capture> -Y 'wlan.ssid=<ssid>' -Tfields -e wlan.bssid` will display the devices that connected to the network
- `tshark -r <capture> -Y 'wlan.ssid=<ssid>' -Tfields -e wlan_radio.channel` will show the channels used in the network
- `tshark -r <capture> -Y 'wlan.fc.type_subtype==0x000c' -Tfields -e wlan.ra` will show the devices that received deauth messages
- `tshark -r <capture> -Y 'wlan.ta==<MAC address> && http' -Tfields -e http.user_agents` will display the traffic tranmitted from the specified MAC address and will show only those ones containing HTTP traffic