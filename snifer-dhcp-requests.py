
import struct
import sys
import socket
import codecs
import DHCPServer_spoofing

global total
total = 0
global bool_packet_ethernet_broadcast 
global ipv4
global destination_port_dhcp
bool_packet_ethernet_broadcast = False
bool_packet_ipv4 = False
bool_packet_destination_port_dhcp = False


def ethernet_head(raw_data):
    #ETHENET ++
 dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
 

 
 protocol = ethernet_protocol_verify(prototype)
 
 #print('\n>ETHERNET FRAME:')
 #print('>...Destination:',':'.join(mac_dest[i:i+2] for i in range(0,12,2))) # exibe o mac formatado
 if (show_mac(dest) == "ff:ff:ff:ff:ff:ff"):
    bool_packet_ethernet_broadcast = True
    
 return protocol

def ethernet_protocol_verify(prototype):#retorna o tipo de protocolo
    protocol_hex = hex(prototype)
    protocol_name='none'
    
    if(prototype == 2048): protocol_name = 'IPv4'
    if(prototype == 34525): protocol_name = 'IPv6'
    if(prototype == 2054): protocol_name = 'ARP'  
    return protocol_hex, protocol_name

def show_mac(hex_mac): #retorna mac formatado
    
    hex_mac = codecs.encode(hex_mac, 'hex')
    mac_utf= hex_mac.decode('utf-8') #decodifica byte
    mac_output = ':'.join(mac_utf[i:i+2] for i in range(0,12,2))
    return mac_output
    
    
def show_ip(hex_ip): #recebe o IP em hexa e retorna em IP formatado
    
    ip_output=''
    for x in range (len(hex_ip)):
        ip_hex = codecs.encode(hex_ip[x:x+1], 'hex')
        ip_output = ip_output + str((int(ip_hex, base=16))) + '.'
        
    ip_output = ip_output[0:len(ip_output)-1] #remover ultimo ponto
    return ip_output

    
def raw_to_string(raw_info):# return transform input -> hex -> utf-8 -> string
    hex_info = codecs.encode(raw_info, 'hex')
    str_rtn = hex_info.decode('utf-8')
    return str_rtn
def ip_protocol_verify(n_protocol):
    protocol_hex = hex(n_protocol)
    protocol_name='none'
    
    if(n_protocol == 1): protocol_name = 'ICMP'
    if(n_protocol == 6): protocol_name = 'TCP'
    if(n_protocol == 17): protocol_name = 'UDP'  
    if (n_protocol == 58): protocol_name = 'ICMPv6'
    if (n_protocol == 59): protocol_name = 'No next Header'

    return protocol_hex, protocol_name
    
    
def ipv4_header(data):
    
    bool_packet_ipv4 = True    
    parse_packet = data[14:] #para identificacao dos cabelhos do IPv4, ficara mais facil apos o parse a contagem comeca em 0
    
    
    
    ttl, proto, src, target = struct.unpack('! B B 2x 4s 4s', parse_packet[8:20]) 
    
    protocol_rtn = ip_protocol_verify(proto)
    return protocol_rtn

    
def ip_head(protocol, data):
    if(protocol[1] == 'none'):
        print("Failed to parse ProtocolType")
        return 'none'
    elif(protocol[1] == 'IPv4'):
        encapsulated_protocol_ip = ipv4_header(data)
        return encapsulated_protocol_ip
    else:
        return 'none'

    
    
    
def udp_head(data):
    parse_packet = data[34:]
    source_port, destination_port, length, checksum = struct.unpack('! H H H 2s', parse_packet[0:8])
    
    if (source_port==68 and destination_port == 67): 
        application = 'DHCP'
    else:
        application = 'none'
    
    return application
    
    pass

def tcp_ip_layer(encapsulated_protocol_ip, raw_data):
    
    if(encapsulated_protocol_ip[1] == 'none'):
        print("Failed to parse ProtocolType")
            
    elif(encapsulated_protocol_ip[1] == 'UDP'):
        protocol_application = udp_head(raw_data)
        return protocol_application    
        
    else:
        return
        

#DHCP
def application_protocol_head(application_protocol, data):
    
    if (application_protocol == 'DHCP'): #DNS Header format 16 bit per line (2 bytes)
        print(">>>>>>>>>>>>DHCP PACKET")
        parse_packet = data[42:]
        for i in range(0, (len(parse_packet)-16), 17):
            print(parse_packet[i:i+17])
            
        #Busca principais campos do DHCP
        message_type=struct.unpack('! s', parse_packet[0:1])
        transation_id = struct.unpack('! 4s', parse_packet[4:8])
        client_mac =struct.unpack('! 6s', parse_packet[28:34])
        magic_cookie  = struct.unpack('! 4s', parse_packet[236:240])
        dhcp_message_type = struct.unpack('! B', parse_packet[242:243])
        
        
        
        print(message_type)
        print(transation_id)
        print(show_mac(client_mac[0]))#precisa o [0] pois em casos simples retorna tupla
        print(magic_cookie)
        print(dhcp_message_type)

        if dhcp_message_type == 1:
            #chamar OFFER
            pass
            
        elif dhcp_message_type ==3:
            #chamar ACK
            pass
          
    
def main():
    global total
    total = 0
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
     raw_data, addr = s.recvfrom(65535)
     #PACOTE TOTAL
     total += 1
     
     encapsulated_protocol_ethernet = ethernet_head(raw_data)
     encapsulated_protocol_ip = ip_head(encapsulated_protocol_ethernet, raw_data)
     application_protocol = tcp_ip_layer(encapsulated_protocol_ip, raw_data)
     application_protocol_head(application_protocol, raw_data)
     
     #funcao calcula estatisticas

     #open (w )
     # % tipo =  tipo / totalpacotes * 100
    
     
     print('===========================================================================')
     print('===========================================================================')
     
     
     

main()
