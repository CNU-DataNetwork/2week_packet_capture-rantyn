from pylibpcap.pcap import sniff
from pylibpcap import get_iface_list
print(get_iface_list())

inner_iface = get_iface_list()[0]

try:
    for plen, t, buf in sniff(inner_iface, filters='src host www.youtube.com', count=5):
        print('[+]: Payload len=', plen)
        print('[+]: Time=', t)
        print('[+]: payload=', buf)
        
    
except KeyboardInterrupt:
    print("exit")
    exit()
    
    
