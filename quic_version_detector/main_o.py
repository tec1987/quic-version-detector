import sys
import asyncio

from quic_version_detector import quic, net, cli


def print_results(
        host: str, port: int,
        version_negotiation_packet: quic.VersionNegotationPacket) -> None:
    """Prints retrieved results.

    Args:
        host: queried hostname.
        port: queried port.
        version_negotation_packet: received packet.
    """
    print('"{}:{}" supported versions:'.format(host, port))
    for version in version_negotiation_packet.supported_versions:
        print('    ', version)


class UdpHandler:
    query_count = 10

    def __init__(self, target_hostname: str, target_port: int) -> None:
        self.target_hostname = target_hostname
        self.target_port = target_port

    def connection_made(self, transport) -> None:
        self.transport = transport

        for _ in range(self.query_count):
            self.transport.sendto(quic.dummy_version_packet().to_buff())

    def datagram_received(self, data, addr) -> None:
        print_results(
            self.target_hostname,
            self.target_port,
            quic.parse_response(data),
        )

        self.transport.close()

    def error_received(self, transport) -> None:
        print('Error received:', transport)

    def connection_lost(self, transport) -> None:
        loop = asyncio.get_event_loop()
        loop.stop()


def stop_event_loop(event_loop, timeout: float) -> None:
    """Terminates event loop after the specified timeout."""
    def timeout_handler():
        event_loop.stop()

        print('Timeout\nExiting...')
    event_loop.call_later(timeout, timeout_handler)


def main() -> None:
    """Main entry point."""
    args = cli.parse_args(sys.argv[1:])

    server_addr = net.resolve_hostname(args.host)

    event_loop = asyncio.get_event_loop()

    connect = event_loop.create_datagram_endpoint(
        lambda: UdpHandler(args.host, args.port),
        remote_addr=(server_addr, args.port)
    )
    event_loop.run_until_complete(connect)

    stop_event_loop(event_loop, 10)
    event_loop.run_forever()


if __name__ == '__main__':
    main()
