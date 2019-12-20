import pyshark
import time
import msgpack
import json

# capture = pyshark.LiveCapture(interface='enp3s0')

# with sniff() method we can capture a given amount of packet
# capture.sniff(timeout=50)

# with sniff_continuously() we can capture every packet that arives
# for packet in capture.sniff_continuously():
#     time.sleep(2)

   

filtered_cap2 = pyshark.LiveCapture(interface='enp3s0',display_filter='http.host == "192.168.1.160"')

for packet in filtered_cap2.sniff_continuously():
    # time.sleep(1)   
    # print(packet)
    # packet.pretty_print()

    # print ('Just arrived:', packet)
    # print("-----------------------------------------------------")
    # packet.pretty_print()
   
    # try:
    #     print(packet.ip.addr.showname)
    # except:
    #     pass
  
    # try:
    #     print(packet.eth)
    # except:
    #     pass

    # try:
    #     print(packet.frame_info)
    # except:
    #     pass

   

    # few more packets we can fetch: (captured_length, interface_captured, sniff_timestamp, transport_layer,
    #                                  udp, layers, length, pretty_print)   

    # try:
    #     protocol =  packet.transport_layer
    #     src_addr = packet.ip.src
    #     src_port = packet[packet.transport_layer].srcport
    #     dst_addr = packet.ip.dst
    #     dst_port = packet[packet.transport_layer].dstport
    #     print ("Protocol: ",protocol,"\n","Src address: ",src_addr,"\n", "Src port: ",
    #      src_port,"\n","Dst address: ", dst_addr,"\n", "Dst port: ", dst_port)
    # except AttributeError as e:
    #     #ignore packets that aren't TCP/UDP or IPv4
    #     pass

    # for current_layer in packet.layers:
        # print(current_layer)
      

    # try:
    #     print(packet.tcp)
    # except:
    #     pass

    # try:
    #     print(packet.tcp.payload)
    #     # print(type(packet.tcp.payload))
    #     # print(packet.tcp.pretty_print())
    # except:
    #     pass
    
    # print(type(packet))
    
### ### ###
    # print(packet.http)

    # protocol = packet.highest_layer
    # if protocol == 'HTTP':

        # print('Time stamp: ',packet.sniff_time)
        # print("SOURCE ADDRESS: ",packet.ip.addr)
        # print("METHOD: ",packet.http.request_method)
        # print("DESTINATION ADDRESS: ",packet.http.host)  
        # print("DESTINATION API: ",packet.http.referer)
        # print("PAYLOAD: ".packet.tcp.payload)

    time_stamp = packet.sniff_time
    source_address = packet.ip.addr
    destination_address = packet.http.host
    method = packet.http.request_method
    destination_api = packet.http.referer
    payload = packet.tcp.payload

    data = {
            "source_address":source_address,
            "destination_address":destination_address,
            "method":method,
            "destination_api":destination_api,
            "payload":payload}
    # print(data)
    # # my_json = json.loads(data)
    # packed_dict = msgpack.packb(data, use_bin_type=True)
    # print(packed_dict)
  
    # converting in msgpack format
    my_data = msgpack.dumps(data)

    # converting in json fromat
    # my_data = json.dumps(data)
    print(my_data)


   
    