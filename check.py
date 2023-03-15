from packet_capture import packetCapture
from pylibpcap import get_iface_list
from pylibpcap.pcap import rpcap

def test_one():
    pc = packetCapture()
    using_iface = get_iface_list()[0]
    for len, t, buf in rpcap('sample_1.pcap'):
        pc.split_header(buf)

    assert pc.result['ethernet_header_dst'] == '08:00:27:80:ae:3c'
    assert pc.result['ethernet_header_src'] == '52:54:00:12:35:02'
    assert pc.result['ip_header_dst'] == '10.0.2.15'
    assert pc.result['ip_header_src'] == '223.130.195.95'
    assert pc.result['tcp_src_port'] == 443
    assert pc.result['tcp_dec_port'] == 38432
    assert pc.result['tcp_seq_num'] == 4489333
    assert pc.result['tcp_ack_num'] == 133066941
    assert pc.result['tcp_checksum'] == 47746
    assert True
    
def test_two():
    pc = packetCapture()
    using_iface = get_iface_list()[0]

    for len, t, buf in rpcap('sample_2.pcap'):
        pc.split_header(buf)

    assert pc.result['ethernet_header_dst'] == '08:00:27:80:ae:3c'
    assert pc.result['ethernet_header_src'] == '52:54:00:12:35:02'
    assert pc.result['ip_header_dst'] == '10.0.2.15'
    assert pc.result['ip_header_src'] == '223.130.195.95'
    assert pc.result['tcp_src_port'] == 443
    assert pc.result['tcp_dec_port'] == 38432
    assert pc.result['tcp_seq_num'] == 4492268
    assert pc.result['tcp_ack_num'] == 133066941
    assert pc.result['tcp_checksum'] == 50651
    
def test_three():
    pc = packetCapture()
    using_iface = get_iface_list()[0]

    for len, t, buf in rpcap('sample_3.pcap'):
        pc.split_header(buf)
    
    print(pc.result.keys())

    assert pc.result['ethernet_header_dst'] == '08:00:27:80:ae:3c'
    assert pc.result['ethernet_header_src'] == '52:54:00:12:35:02'
    assert pc.result['ip_header_dst'] == '10.0.2.15'
    assert pc.result['ip_header_src'] == '192.168.1.1'
    assert pc.result['udp_dst_port'] == 42703
    assert pc.result['udp_src_port'] == 53
    assert pc.result['udp_leng'] == 68