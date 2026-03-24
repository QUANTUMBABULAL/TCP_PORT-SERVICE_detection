import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TIMEOUT = 0.35
DEFAULT_WORKERS = 64
COMMON_PORT_SCAN_LIMIT = 1024
COMMON_PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
}


def _validate_ip(ip_address: str) -> str:
    try:
        return str(ipaddress.ip_address(ip_address))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip_address}") from exc


def _validate_port_range(start_port: int, end_port: int) -> tuple[int, int]:
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        raise ValueError("Invalid port range.")
    return start_port, end_port


def scan_port(ip_address: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    ip_address = _validate_ip(ip_address)
    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        return connection.connect_ex((ip_address, port)) == 0


def service_name_for_port(port: int) -> str:
    return COMMON_PORT_SERVICES.get(port, "Unknown")


def scan_ports(
    ip_address: str,
    start_port: int = 1,
    end_port: int = COMMON_PORT_SCAN_LIMIT,
    timeout: float = DEFAULT_TIMEOUT,
    workers: int = DEFAULT_WORKERS,
) -> list[int]:
    ip_address = _validate_ip(ip_address)
    start_port, end_port = _validate_port_range(start_port, end_port)

    open_ports: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip_address, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                open_ports.append(
                    {
                        "port": port,
                        "status": "Open",
                        "service": service_name_for_port(port),
                    }
                )

    return sorted(open_ports, key=lambda item: item["port"])


def scan_network(subnet: str = "192.168.1.0/24", timeout: float = DEFAULT_TIMEOUT) -> list[dict[str, object]]:
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet: {subnet}") from exc

    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=DEFAULT_WORKERS) as executor:
        futures = {
            executor.submit(_scan_host, str(host), timeout): str(host)
            for host in network.hosts()
        }
        for future in as_completed(futures):
            result = future.result()
            if result["open_ports"]:
                results.append(result)

    results.sort(key=lambda item: item["ip"])
    return results


def _scan_host(ip_address: str, timeout: float) -> dict[str, object]:
    open_ports: list[dict[str, object]] = []
    for port in (22, 80, 443, 445, 3389):
        try:
            if scan_port(ip_address, port, timeout=timeout):
                open_ports.append(
                    {
                        "port": port,
                        "status": "Open",
                        "service": service_name_for_port(port),
                    }
                )
        except OSError:
            continue
    return {"ip": ip_address, "open_ports": open_ports}
