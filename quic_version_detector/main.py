import sys
import asyncio

from quic_version_detector import quic, net, cli


def print_results(host, port ,version_negotation_packet):
    """Prints retrieved results.

    Args:
        host (str): queried hostname.
        port (int): queried port.
        version_negotation_packet (quic.VersionNegotationPacket)
    """
    print('"{}:{}" supported versions:'.format(host, port))
    for version in version_negotation_packet.supported_versions:
        print('    ', version)

class UdpHandler:

    def __init__(self, target_hostname, target_port):
        self.target_hostname = target_hostname
        self.target_port = target_port

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(quic.dummy_version_packet().to_buff())

    def datagram_received(self, data, addr):
        print_results(
            self.target_hostname,
            self.target_port,
            quic.parse_response(data),
        )

        self.transport.close()

    def error_received(self, transport):
        print('Error received:', transport)

    def connection_lost(self, transport):
        loop = asyncio.get_event_loop()
        loop.stop()


def main():
    """Main entry point."""
    args = cli.parse_args(sys.argv[1:])

    server_addr = net.resolve_hostname(args.host)

    event_loop = asyncio.get_event_loop()

    connect = event_loop.create_datagram_endpoint(
        lambda: UdpHandler(args.host, args.port),
        remote_addr=(server_addr, args.port)
    )

    event_loop.run_until_complete(connect)
    event_loop.run_forever()


if __name__ == '__main__':
    main()
