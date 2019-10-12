#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys, time, os, struct, random
import asyncio


def data_coll(_rtt):
    global recv_i, sum_rtt

    recv_i += 1
    sum_rtt += _rtt


def len_data_head(data):
    len_idh = 1     # data[0]
    len_version = 4 # data[1:5]
    len_DCIL = 1    # data[5]
    len_DCID = data[len_idh + len_version]  # data[6:6+len_DCIL]
    len_SCIL = 1    # data[6+len_DCIL]
    len_SCID = data[len_idh + len_version + len_DCIL + len_DCID]
    return 7 + len_DCID + len_SCID  # 7 + data[6+data[5]] + data[5]


def dummy_version_packet(f):        # 1:23   0:15
    if f:   # QUIC Long Header	[8-f][0-f] 00000000(32bitVer) DCID Len == SCID Len == 8
        # qdata = struct.pack('!B',random.randint(0,255)|0x80) + b'\x00\x00\x00\x00\x50' + os.urandom(8)
        qdata = struct.pack('!B',random.randint(0,255)|0x80) + struct.pack('!L',random.randint(0,0xffffffff)&0xfafafafa|0x0a0a0a0a) + b'\x08' + os.urandom(8) + b'\x08' + os.urandom(8) + b'\x00'*1177
        len_h = 23
    else:   # SCID Len == 0  DCID Len == [8,20]
        # qdata = struct.pack('!B',random.randint(0,255)&0x7d|9) + os.urandom(8) + struct.pack('!L',random.randint(0,0xffffffff)&0xfafafafa|0x0a0a0a0a)    # '\x00\x00\x00\x00'
        _rl = random.randint(8,0x14)
        qdata = struct.pack('!B',random.randint(0,255)|0x80) + random.choice([b'\xff',b'\x00']) + os.urandom(3) + struct.pack('!B',_rl) + os.urandom(_rl) + b'\x00'*1186
        len_h = 7 + _rl
    print('\tSend Query: %s'%' '.join('%02X'%x for x in qdata[:len_h]))
    return qdata
    '''
    struct.pack('!B',random.randint(0,255)&0x7d|9)  # random.randint(0,7)*16+9+random.choice([0,4])     [0-7][9|d]
    struct.pack('!Q',random.randint(0,0xFFFFFFFFFFFFFFFF))  # os.urandom(8) CID(64bit)
    struct.pack('!L',random.randint(0,0xffffffff)&0xfafafafa|0x0a0a0a0a)    # '*a*a*a*a'    Ver(32bit)
    '''

class UdpHandler:
    global query_count

    def __init__(self, target_hostname, target_port):
        self.target_hostname = target_hostname
        self.target_port = target_port
        self.recv_count = 0

    def connection_made(self, transport):
        self.transport = transport
        self.s_time = time.time()

        for _ in range(query_count):
            self.transport.sendto(dummy_version_packet(random.randint(0,1)))	# random.randint(0,1)

    def datagram_received(self, data, addr):
        global QUIC_Ver
        if self.recv_count == 0:
            len_h = len_data_head(data)
            QUIC_Ver = str(data[len_h:])[2:-1] # .decode('utf8','ignore')
        self.recv_count += 1
        print('  Recv Data:\t(%d/%d)\n    %r'%(self.recv_count, query_count, data))
        data_coll(time.time() - self.s_time)
        # print('"{}:{}" is enabled QUIC.\tRTT={}ms'.format(self.target_hostname, self.target_port, time.time() - self.s_time))
        if self.recv_count == query_count: self.transport.close()

    def error_received(self, transport):
        print('"{}:{}"\t{}'.format(self.target_hostname, self.target_port, transport))
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
    global recv_i, sum_rtt, query_count
    recv_i = sum_rtt = 0
    query_count = 3
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
        print('"{}:{}" is enabled QUIC. ({})\tRTT={:.2f}ms\t{}/{}'.format(server_addr, query_port, QUIC_Ver, sum_rtt*1000/recv_i, recv_i, query_count))
        with open('QUIC-r.txt', 'a') as wf: wf.write('%s\t%s\t%.2f\t%d|%d\t%s\n'%(time.strftime('%Y%m%d %X'), server_addr, sum_rtt*1000/recv_i, recv_i, query_count, QUIC_Ver))

if __name__ == '__main__':
    main()
