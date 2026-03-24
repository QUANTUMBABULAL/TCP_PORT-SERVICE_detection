import csv
import io
import json
from typing import Any

from scanner import service_name_for_port


def build_report_payload(report_type: str, data: dict[str, Any]) -> tuple[str, str, str]:
    if report_type not in {"network", "ports"}:
        raise ValueError("Unsupported report type.")

    export_format = (data.get("format") or "json").lower()
    if export_format not in {"json", "csv"}:
        raise ValueError("Unsupported export format.")

    if report_type == "network":
        return _build_network_report(export_format, data)
    return _build_port_report(export_format, data)


def _build_network_report(export_format: str, data: dict[str, Any]) -> tuple[str, str, str]:
    subnet = data.get("subnet", "192.168.1.0/24")
    results = data.get("results", [])
    filename_base = "network-scan-report"

    if export_format == "json":
        payload = {
            "report_type": "network",
            "subnet": subnet,
            "results": results,
        }
        return (
            json.dumps(payload, indent=2),
            f"{filename_base}.json",
            "application/json",
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ip", "open_port_count", "open_ports"])
    for device in results:
        open_ports = device.get("open_ports", [])
        port_values = ", ".join(str(item.get("port")) for item in open_ports)
        writer.writerow([device.get("ip", ""), len(open_ports), port_values])
    return output.getvalue(), f"{filename_base}.csv", "text/csv"


def _build_port_report(export_format: str, data: dict[str, Any]) -> tuple[str, str, str]:
    ip_address = data.get("ip", "")
    results = data.get("results", [])
    filename_base = f"port-scan-report-{ip_address or 'host'}"

    if export_format == "json":
        payload = {
            "report_type": "ports",
            "ip": ip_address,
            "results": results,
        }
        return (
            json.dumps(payload, indent=2),
            f"{filename_base}.json",
            "application/json",
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["port", "status", "service"])
    for item in results:
        port = item.get("port", "")
        service = item.get("service") or service_name_for_port(int(port)) if str(port).isdigit() else "Unknown"
        writer.writerow([port, item.get("status", "Open"), service])
    return output.getvalue(), f"{filename_base}.csv", "text/csv"
