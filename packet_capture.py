import struct
from pylibpcap import get_iface_list
from pylibpcap.pcap import rpcap


class packetCapture():

    def __init__(self) -> None:
        self.result = dict()

    def split_header(self, data):
        ethernet_header = data[0:14]
        ip_header = data[14:34]
        transport_header = data[34:54]

        self.eth_header_parser(ethernet_header)
        transport_protocol = self.ip_header_parser(ip_header)

        if transport_protocol == format(6, '02x'):
            self.tcp_header_parser(transport_header)
        elif transport_protocol == format(17, '02x'):
            self.udp_header_parser(transport_header)
        else:
            print("current function can't capture.")

    def eth_header_parser(self, data):
        ethernet_header = struct.unpack("!6c6c2s", data)

        src_ethernet_addr = list()
        dst_ethernet_addr = list()

        for dst_i in ethernet_header[0:6]:
            dst_ethernet_addr.append(dst_i.hex())
        for src_i in ethernet_header[6:12]:
            src_ethernet_addr.append(src_i.hex())

        ip_header = ethernet_header[12:][0].hex()

        dst_ethernet_addr = ":".join(dst_ethernet_addr)
        src_ethernet_addr = ":".join(src_ethernet_addr)

        self.result['ethernet_header_dst'] = dst_ethernet_addr
        self.result['ethernet_header_src'] = src_ethernet_addr

        print("###### [ Ethernet_header ]######")
        print("Destination Address:", dst_ethernet_addr)
        print("Source Address:", src_ethernet_addr)
        print("Type:", "0x" + ip_header)

    def ip_header_parser(self, data):
        ip = struct.unpack("!BBHHHccH4c4c", data)

        ip_version = ip[0] >> 4  # ip[0]이 69인데, 1000101이다. >>4로 4가 되며, IPv4를 나타냄
        ip_Length = ip[0] & 5  # Header Length로 5를 나타낸다. (20bytes)

        total_length = ip[2]

        ttl = int(ip[5].hex(), 16)  # ip[5].hex()를 16진수로 한걸 다시 10진수로)

        protocol = ip[6].hex()  # 0x06은 tcp, 0x11은 udp

        header_checksum = ip[7]

        src_ip = list()
        dest_ip = list()

        ## 작성 필요 ##
        for i in ip[8:12]:
            src_ip.append(str(int(i.hex(),16)))
        for i in ip[12:16]:
            dest_ip.append(str(int(i.hex(), 16)))
        ###############

        src_ip = ".".join(src_ip)
        dest_ip = ".".join(dest_ip)

        self.result['ip_header_dst'] = dest_ip
        self.result['ip_header_src'] = src_ip

        # 출력
        print("######[ Ip_header ]######")
        print("Version:", ip_version)
        print("IHL (Header Length):", ip_Length)
        print("Total Length:", total_length)
        print("Time To Live:", ttl)
        print("Protocol:", protocol)
        print("Header Checksum:", "0x" + str(format(header_checksum, '02x')))
        print("Source Address:", src_ip)
        print("Destination Address:", dest_ip)

        return protocol

    def tcp_header_parser(self, data):
        tcp = struct.unpack("!HHLLHHHH", data)

        src_port  = tcp[0]
        dec_port  = tcp[1]
        seq_num   = tcp[2]
        ack_num   = tcp[3]
        checksum  = tcp[6]


        ## 작성 필요 ##

        ###############

        self.result['tcp_src_port'] = src_port
        self.result['tcp_dec_port'] = dec_port
        self.result['tcp_seq_num'] = seq_num
        self.result['tcp_ack_num'] = ack_num
        self.result['tcp_checksum'] = checksum

        # 출력
        print("###[ TCP_header ]###")
        print("Source Port:", src_port)
        print("Destination Port:", dec_port)
        print("Sequence Number:", seq_num)
        print("Acknowledgement Number:", ack_num)
        print("Checksum:", checksum)

    def udp_header_parser(self, data):
        udp = struct.unpack("!HHHH", data[0:8])

        ## 작성 필요 ##

        #######
        src_port = udp[0]
        dst_port = udp[1]
        leng     = udp[2]
        checksum = udp[3]
        

        self.result['udp_src_port'] = src_port
        self.result['udp_dst_port'] = dst_port
        self.result['udp_leng'] = leng
        self.result['udp_checksum'] = checksum

        print("######[ UDP_header ]######")
        print("Source Port:", src_port)
        print("Destination Port:", dst_port)
        print("Length:", leng)
        print("Checksum:", "0x" + str(format(checksum, '02x')))


if __name__ == '__main__':
    pc = packetCapture()
    using_iface = get_iface_list()[0]

    for len, t, buf in rpcap('sample_2.pcap'):
        pc.split_header(buf)
