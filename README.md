# Network Scanner Dashboard

This project is a small Flask web app for discovering devices on a local network, checking open ports on a selected host, and exporting scan results as JSON or CSV.

## Aim

The goal of the app is to provide a simple browser-based dashboard for basic network visibility:

- scan a subnet for active hosts
- inspect common ports on a selected device
- export scan results for later review or sharing

## Features

- Web dashboard built with Flask and Bootstrap
- Local network scan for devices that respond on common ports
- Port scan for ports 1 through 1024 on a selected host
- JSON and CSV report export
- Responsive UI with live results shown in the browser

## Project Structure

- `app.py` - Flask routes and app startup
- `scanner.py` - network and port scanning logic
- `report_export.py` - JSON and CSV report generation
- `templates/index.html` - dashboard UI
- `requirements.txt` - Python dependency list

## Requirements

- Python 3.10 or newer
- A network you are authorized to scan

## Setup

1. Create and activate a virtual environment:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\\Scripts\\Activate.ps1
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the App

Start the Flask server:

```bash
python app.py
```

Then open the dashboard in your browser at:

```text
http://127.0.0.1:5000
```

## How to Use

1. Enter a subnet in CIDR format, such as `192.168.1.0/24`.
2. Click **Scan Network** to find active devices.
3. Select a device from the list to scan its ports.
4. Choose `JSON` or `CSV` and download a report.

## Backend Endpoints

- `GET /` - dashboard page
- `GET` or `POST /scan-network` - scan a subnet
- `GET` or `POST /scan-ports` - scan ports on a single host
- `POST /download-report` - export scan results

## Notes

- The network scan checks common ports such as SSH, HTTP, HTTPS, SMB, and RDP.
- Port scans currently cover ports 1 through 1024.
- If a subnet or IP address is invalid, the API returns a validation error.
- Only scan systems and networks you own or are explicitly authorized to test.

## Troubleshooting

- If the dashboard does not load, confirm the Flask server is running and that port 5000 is free.
- If scans return no results, the target hosts may be offline, blocked by a firewall, or on a different subnet.
- If PowerShell blocks activation of the virtual environment, run the session as needed with the correct execution policy for your machine.
