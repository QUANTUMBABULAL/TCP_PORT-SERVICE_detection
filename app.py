from io import BytesIO

from flask import Flask, jsonify, render_template, request, send_file

from scanner import scan_network, scan_ports
from report_export import build_report_payload

app = Flask(__name__)


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/scan-network", methods=["GET", "POST"])
def scan_local_network():
    subnet = request.args.get("subnet", "192.168.1.0/24")
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        subnet = payload.get("subnet", subnet)

    try:
        results = scan_network(subnet)
        return jsonify({"success": True, "subnet": subnet, "results": results})
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400


@app.route("/scan-ports", methods=["GET", "POST"])
def scan_open_ports():
    ip_address = request.args.get("ip", "")
    if request.is_json:
        payload = request.get_json(silent=True) or {}
        ip_address = payload.get("ip", ip_address)

    if not ip_address:
        return jsonify({"success": False, "error": "An IP address is required."}), 400

    try:
        results = scan_ports(ip_address, 1, 1024)
        return jsonify({"success": True, "ip": ip_address, "results": results})
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400


@app.route("/download-report", methods=["POST"])
def download_report():
    payload = request.get_json(silent=True) or {}
    report_type = payload.get("report_type")

    try:
        content, filename, mimetype = build_report_payload(report_type, payload)
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    buffer = BytesIO(content.encode("utf-8"))
    response = send_file(
        buffer,
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename,
    )
    response.headers["X-Download-Filename"] = filename
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
