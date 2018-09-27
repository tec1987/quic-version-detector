#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys, time, os, struct, random
import asyncio

# from quic_version_detector import quic, cli, net
'''
def print_results(host, port, version_negotation_packet, rtt, recv_count, query_count):
    """Prints retrieved results.

    Args:
        host (str): queried hostname.
        port (int): queried port.
        version_negotation_packet (quic.VersionNegotationPacket)
    """
    for version in version_negotation_packet.supported_versions:
        print('    ', version)
    '''
    # print('"{}:{}" is enabled QUIC.\tRTT={}ms\t{}/{}'.format(host, port, rtt*1000, recv_count, query_count))
    # with open('QUIC-r.txt', 'a') as wf: wf.write('%s\t%s\t%.2f\n'%(time.strftime('%c'), host, rtt*1000))

def data_coll(_rtt):
    global recv_i, sum_rtt
    if _rtt:
        recv_i += 1
        sum_rtt += _rtt
    else:
        return recv_i, sum_rtt/recv_i

def dummy_version_packet(f):
    if f:   # [8-f][0-f] 00000000(32bitVer) 50 CID(64bit)	QUIC Long Header
        qdata = struct.pack('!B',random.randint(0,255)|0x80) + b'\x00\x00\x00\x00\x50' + os.urandom(8)
    else:   # [0-7][9|d] CID(64bit) Ver(32bit)	GQUIC Short Header
        qdata = struct.pack('!B',random.randint(0,255)&0x7d|9) + os.urandom(8) + struct.pack('!L',random.randint(0,0xffffffff)&0xfafafafa|0x0a0a0a0a)    # '\x00\x00\x00\x00'
    print('\tSend Query: %s'%' '.join('%02X'%x for x in qdata))
    return qdata
    '''
    struct.pack('!B',random.randint(0,255)&0x7d|9)  # random.randint(0,7)*16+9+random.choice([0,4])     [0-7][9|d]
    struct.pack('!Q',random.randint(0,0xFFFFFFFFFFFFFFFF))  # os.urandom(8) CID(64bit)
    struct.pack('!L',random.randint(0,0xffffffff)&0xfafafafa|0x0a0a0a0a)    # '*a*a*a*a'    Ver(32bit)
    '''

class UdpHandler:
    query_count = 3

    def __init__(self, target_hostname, target_port):
        self.target_hostname = target_hostname
        self.target_port = target_port
        self.recv_count = 0

    def connection_made(self, transport):
        self.transport = transport
        self.s_time = time.time()

        for _ in range(self.query_count):
            self.transport.sendto(dummy_version_packet(random.choice([0,0,0,1,1,1])))

    def datagram_received(self, data, addr):
        self.recv_count += 1
        print('%d/%d\tRecv Data:%r'%(self.recv_count, self.query_count, data))
        data_coll(time.time() - self.s_time)

        '''
        print_results(
            self.target_hostname,
            self.target_port,
            #quic.parse_response(data),
            None,
            time.time() - self.s_time,
            self.recv_count,
            self.query_count
        )'''
        # print('"{}:{}" is enabled QUIC.\tRTT={}ms'.format(self.target_hostname, self.target_port, time.time() - self.s_time))

        if self.recv_count == self.query_count: self.transport.close()

    def error_received(self, transport):
        print('Error received:', transport)
        self.transport.close()

    def connection_lost(self, transport):
        loop = asyncio.get_event_loop()
        loop.stop()


def stop_event_loop(event_loop, timeout, s_addr, q_port):
    """Terminates event loop after the specified timeout."""
    def timeout_handler():
        event_loop.stop()

        print('"{}:{}" \tTimeout...\t{}ms'.format(s_addr, q_port, timeout*1000))
    event_loop.call_later(timeout, timeout_handler)


def main():
    """Main entry point."""
    #print("Start:",time.ctime(), time.time())
    global recv_i, sum_rtt
    recv_i = sum_rtt = 0
    query_timeout = 1.6
    query_port = 443
    server_addr = "127.0.0.1"
    if len(sys.argv) > 1 : server_addr = sys.argv[1]
    if len(sys.argv) > 2 : query_port = sys.argv[2]
#    args = cli.parse_args(sys.argv[1:])
#    server_addr = net.resolve_hostname(args.host)

    event_loop = asyncio.get_event_loop()
    connect = event_loop.create_datagram_endpoint(
        lambda: UdpHandler(server_addr, query_port),
        remote_addr=(server_addr, query_port)
    )
    event_loop.run_until_complete(connect)
    stop_event_loop(event_loop, query_timeout, server_addr, query_port)
    event_loop.run_forever()
    #print("End:",time.ctime(), time.time())
    if recv_i:
        recv_count, _rtt = data_coll(None)
        print('"{}:{}" is enabled QUIC.\tRTT={}ms\t{}/{}'.format(server_addr, query_port, _rtt*1000, recv_count, UdpHandler.query_count))
        with open('QUIC-r.txt', 'a') as wf: wf.write('%s\t%s\t%.2f\t%d/%d\n'%(time.strftime('%c'), server_addr, _rtt*1000, recv_count, UdpHandler.query_count))

if __name__ == '__main__':
    main()
