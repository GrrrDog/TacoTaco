#!/usr/bin/python
__author__ = 'GreenDog'
import hashlib
import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description="A converter of a Tacacs+ packet to a format of HashCat. ")

    parser.add_argument(
        '-t', '--type', type=str, help="Type of a packet (in HEX). \1 - SSH, a packet from a cisco device to a tacacs+ server. You should set 12345678 as a username; " +
                                       "2 - Telnet, a packet from a tacacs+ server to a cisco device. "+
                                       "You should set a greeting meesage of the cisco device in -m. "+
                                       "A default value is \"\\nUser Access Verification\\n\\nUsername: \". Set \"Password:\" for SSH",  required=True)
    parser.add_argument(
        '-m', '--mess', type=str, help='Message or IP depending on the type of the packet', default="\nUser Access Verification\n\nUsername: ", required=False)

    parser.add_argument(
        '-p', '--packet', type=str, help='Tacacs+ packet in hex', required=True)
    parser.add_argument(
        '-v', '--verbose', help='Verbose mode', action="store_true", dest="verbose", default=False, required=False)
    args = parser.parse_args()
    return args.type, args.packet, args.mess, args.verbose


def verb(x):
    if verbose:
        print x

print("Tac2Cat / Tacacs+ to HashCat  v0.2 beta")
print("Alexey Tyurin - agrrrdog [at] gmail.com")
print

p_type, packet, message,verbose = parse_args()
vers=packet[0:2]
seq_num = packet[4:6]
ses_id =packet[8:16]
verb("Tacacs+ version: "+vers)
verb("Packen number: "+seq_num)
verb("Session id: "+ses_id)
length=int(packet[16:24],16)
verb("Packet length: "+str(length))

enc_data=packet[24:24+32]
verb("Encrypted data: " + enc_data)

if(p_type=="1"):
    print("Type 1 - SSH")
    len_mes="0%x" % len(message)

    hash_file = open("hashes.txt", "w")
    ip_len="0%x" %(length-20)
    verb("ip length: "+str(ip_len))
    #headers + + static username (12345678)
    data = "01"+ "01"+ "01" + "01"+ "08"+ "04"+ip_len+ "00" + "3132333435363738"
    verb("data: "+data)

    md5_1=hex(int(data, 16) ^ int(enc_data, 16))[2:34]
    print("md5_1 : "+md5_1)
    hash_file.write("%s:%s%s\n" % (md5_1, vers,seq_num))

    print("hashes.txt was created")
    print("hashcat-cli64.exe -a 3 -m 10 --hex-charset --hex-salt hashes.txt %s?your_mask_here"%ses_id)
    hash_file.close()


elif(p_type=="2"):

    print("Type 2")
    message=message.replace('\\n', "\n")
    mes_hex=message[0:10].encode('hex')
    verb("Part of message in hex: "+mes_hex)
    len_mes="%x" % len(message)
    #hex(len(message))[2:]
    hash_file = open("hashes.txt", "w")
    data = "04"+ "00"+ "00"+ len_mes + "00"+ "00" +mes_hex
    verb("data: "+data)

    md5_1=hex(int(data, 16) ^ int(enc_data, 16))[2:34]
    print("md5_1 : "+md5_1)
    hash_file.write("%s:%s%s\n" % (md5_1, vers,seq_num))
    print("hashes.txt was created")
    print("hashcat-cli64.exe -a 3 -m 10 --hex-charset --hex-salt hashes.txt %s?your_mask_here"%ses_id)
    hash_file.close()

else:
    print("Incorrect type of packet")
