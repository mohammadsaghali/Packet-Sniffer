import socket
import struct
import textwrap

tab1 = '\t -'
tab2 = '\t\t -'
tab3 = '\t\t\t -'
dTab3 = '\t\t\t '


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        rawData, addr = conn.recvfrom(65536)
        desMac, srcMac, proto, data = ethernetFrame(rawData)
        print('\nEthernet Frame: ')
        print('Destination: {}, Source: {}, Protocol: {}'.format(desMac, srcMac, proto))
        if proto == 8:
            version, headerLenght, ttl, proto, src, dest, data = ipv4Packet(data)
            print(tab1 + 'IPV4 Packet:')
            print(tab2 + 'version: {} Header Length: {} , TTL: {}'.format(version, headerLenght, ttl))
            print(tab2 + 'Protocol: {} Source: {} , Destination: {}'.format(proto, src, dest))
            if proto == 1:
                icmpType, code, checksum, data = icmp(data)
                print(tab1 + 'ICMP Packet: ')
                print(tab2 + 'Type: {} Code: {} , Checksum: {}'.format(icmpType, code, checksum))
                print(tab2 + 'data: ')
                print(multiLine(dTab3, data))
            elif proto == 6:
                srcPort, destPort, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp(data)
                print(tab1 + 'TCP Segment: ')
                print(tab2 + 'Source Port: {} Destination Port: {}'.format(srcPort, destPort))
                print(tab2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgement))
                print(tab2 + 'Flags: ')
                print(tab3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(tab2 + 'Data: ')
                print(multiLine(dTab3, data))

            elif proto == 17:
                srcPort, destPort, size, data = udp(data)
                print(tab1 + 'UDP Segment: ')
                print(tab2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(srcPort, destPort, size))

            else:
                print(tab1 + 'Data: ')
                print(multiLine(dTab3, data))


def ethernetFrame(data):
    dest, source, protocol = struct.unpack('! 6s 6s H', data[:14])
    return macAddres(dest), macAddres(source), socket.htons(protocol), data[14:]

def macAddres(byteAddres):
    byteStr = map('{:02x}'.format,byteAddres)
    return ':'.join(byteStr).upper()

def ipv4Packet(data):
    version_And_HeaderLenght = data[0]
    version = version_And_HeaderLenght >> 4
    headerLenght = (version_And_HeaderLenght & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, headerLenght, ttl, proto, ipv4(src), ipv4(dest), data[headerLenght:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp(data):
    icmpType,code ,checksum= struct.unpack('!BBH',data[:4])
    return icmpType,code,checksum,data[4:]
def tcp(data):
    srcPort, destPort, sequence, acknowledgement, offsetReservedFLAGS = struct.unpack('!HHLLH',data[:14])
    offset = (offsetReservedFLAGS >> 12) * 4
    flag_urg = (offsetReservedFLAGS & 32) >> 5
    flag_ack = (offsetReservedFLAGS & 16) >> 4
    flag_psh = (offsetReservedFLAGS & 8) >> 3
    flag_rst = (offsetReservedFLAGS & 4) >> 2
    flag_syn = (offsetReservedFLAGS & 2) >> 1
    flag_fin = (offsetReservedFLAGS & 1)
    return srcPort, destPort, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
def udp(data):
    srcPort, destPort, size = struct.unpack('!HH 2x H', data[:8])
    return srcPort, destPort, size, data[8:]
def multiLine(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()