# import pydivert

# # Capture only TCP packets to port 80, i.e. HTTP requests.
# w = pydivert.WinDivert("tcp.DstPort == 443 and tcp.PayloadLength > 0")

# w.open()  # packets will be captured from now on

# packet = w.recv()  # read a single packet
# print(packet.payload)
# # w.send(packet)  # re-inject the packet into the network stack

# # w.close()  # stop capturing packets


import pydivert
import re


def check_format_URL(url):
    return  re.findall(r'(http|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)

def extract_url_http(payload_tcp):
    start_string='Host: '
    end_string='\r\nConnection'
    start_index = payload_tcp.find(start_string.encode())
    end_index = payload_tcp.find(end_string.encode())
    host = payload_tcp[start_index+6:end_index]

    start_string ='GET '
    end_string = ' HTTP'
    start_index=payload_tcp.find(start_string.encode())
    end_index=payload_tcp.find(end_string.encode())
    path =payload_tcp[start_index+4:end_index]
    #print("Hostname: ",host," path: ",path)
    url =host+path
    
    print("http://"+url.decode())

    if len(url)!=0 and check_format_URL(url.decode()):
        url = url.decode()
        print(url)
        return url
    return ""

def extract_url(payload_tcp, dst_port):
    if dst_port == 80:
        #return extract_url_http(payload_tcp)
        print ("pass")
    if dst_port == 443:
        return extract_url_https(payload_tcp)


def extract_url_https(payload_tcp):
    start_index = 127
    end_string = '\x00\x17'

    end_index = payload_tcp.find(end_string.encode('utf-8'), start_index)
    url = payload_tcp[start_index:end_index]
    print(url)
    #print(url)
    #if len(url)!=0 and check_format_URL(payload_tcp.decode('utf-8','backslashreplace')):
    #   url = url.decode('utf-8', 'backslashreplace')
    #    return url
    #return ""
    #ints = list(payload_tcp)
    #print(tlv8.decode(payload_tcp))
    # u = unicode(payload_tcp, 'UTF-8')
    #print(payload_tcp.decode(encoding="utf-8"))
    
    #print(payload_tcp.decode('utf-8', 'backslashreplace'))

with pydivert.WinDivert("(tcp.DstPort == 443) and tcp.PayloadLength > 0") as w:
    for packet in w:
        #s = "aninyviet.com"
        #print(check_format_URL(s))
        #extract_url(packet.payload,packet.dst_port)
        extract_url_https(packet.payload)
        #print(packet.payload)
        print("#####################################################################")
        w.send(packet)







