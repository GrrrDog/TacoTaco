# TacoTaco
TacoTaco is a project about attacks on TACACS+ protocol.

1) tac2cat.py - A converter of a TACACS+ packet to a format of the HashCat. The script helps you to extract a MD5_1 hash from a TACACS+ authentication packet. Then you can perform a local brute force attack on the MD5 hash and get a PSK.

Example:

  python tac2cat.py -t 1  -m "Password: " -p c0010200acf4c30b00000010c73c409532a4a80e58ba94391111e300

Where:

  -t 1 – 1 – SSH, 2 - Telnet
  -m "Password: " – a greeting message from a ssh service of a Cisco device
  -p – a hex stream of the second packet (TACACS+ layer) from the Wireshark.

2) tacoflip.py is a script that you the opportunity to bypass authentication and authorization on a Cisco device that uses a TACACS+ server for AAA. You just need to perform a MitM attack on the Cisco device and the TACACS+ server (arp spoofing, for example)

Example:

  python tacoflip.py –t 192.168.0.100

Where 192.168.0.100 is an IP address of a TACACS+ server

The video shows whole process of the attack: http://www.youtube.com/watch?v=HdTib8wftHA

3) sample dir consists some examples: a router config, a tac_plus config and pcap files of authentication process (telnet, ssh).
