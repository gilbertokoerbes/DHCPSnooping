from socket import *

def udp_calc_checksum(msg:bytes)->int:#http://dontpad.com/redescheck
    sum = 0
    msg = (msg + b'\x00') if len(msg) % 2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        sum = sum + w
        sum = (sum & 0xffff) + (sum >> 16)
    sum = ~sum & 0xffff
    return socket.ntohs(sum)