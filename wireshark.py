import socket
import struct
import textwrap
import time

tab1 = '\t -'
tab2 = '\t\t -'
tab3 = '\t\t\t -'
dTab3 = '\t\t\t '


def main():
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        rawData, addr = conn.recvfrom(65535)
        pcap.write(rawData)
        desMac, srcMac, proto, data = ethernetFrame(rawData)
        print('\nEthernet Frame: ')
        print('Destination: {}, Source: {}, Protocol: {}'.format(desMac, srcMac, proto))

        #IPV4
        if proto == 8:
            version, headerLenght, ttl, proto, src, dest, data = ipv4Packet(data)
            print(tab1 + 'IPV4 Packet:')
            print(tab2 + 'version: {} Header Length: {} , TTL: {}'.format(version, headerLenght, ttl))
            print(tab2 + 'Protocol: {} Source: {} , Destination: {}'.format(proto, src, dest))

            #ICMP
            if proto == 1:
                icmpType, code, checksum, data = icmp(data)
                print(tab1 + 'ICMP Packet: ')
                print(tab2 + 'Type: {} Code: {} , Checksum: {}'.format(icmpType, code, checksum))
                print(tab2 + 'data: ')
                print(multiLine(dTab3, data))

            #TCP
            elif proto == 6:
                srcPort, destPort, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp(data)
                print(tab1 + 'TCP Segment: ')
                print(tab2 + 'Source Port: {} Destination Port: {}'.format(srcPort, destPort))
                print(tab2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgement))
                print(tab2 + 'Flags: ')
                print(tab3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(tab2 + 'Data: ')
                print(multiLine(dTab3, data))

                #HTTP
                if len(data) > 0:
                 if srcPort == 80 or destPort == 80:
                     print(tab2 + 'HTTP Data:')
                     try:
                         http = HTTP(data)
                         http_info = str(http).split('\n')
                         for line in http_info:
                             print(dTab3 + str(line))
                     except:
                         print(multiLine(dTab3, data))
                 else:
                     print(tab2 + 'TCP Data:')
                     print(multiLine(dTab3, data))

            #UDP
            elif proto == 17:
                srcPort, destPort, size, data = udp(data)
                print(tab1 + 'UDP Segment: ')
                print(tab2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(srcPort, destPort, size))

            #OTHER PORTOCOLS
            else:
                print(tab1 + 'Data: ')
                print(multiLine(dTab3, data))

    pcap.close()


def ethernetFrame(data):
    dest, source, protocol = struct.unpack('! 6s 6s H', data[:14])
    return macAddres(dest), macAddres(source), socket.htons(protocol), data[14:]


def macAddres(byteAddres):
    byteStr = map('{:02x}'.format, byteAddres)
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
    icmpType, code, checksum = struct.unpack('!BBH', data[:4])
    return icmpType, code, checksum, data[4:]


def tcp(data):
    srcPort, destPort, sequence, acknowledgement, offsetReservedFLAGS = struct.unpack('!HHLLH', data[:14])
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


def HTTP(data):
    try:
        return data.decode('utf-8')
    except:
        return data



#save file .pcap
class Pcap:
    def __init__(self, filename, type =1):
        self.pcapFile = open(filename, 'wb')
        self.pcapFile.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcapFile.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcapFile.write(data)

    def close(self):
        self.pcapFile.close()

main()