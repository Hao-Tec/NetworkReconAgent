"""
Reporter Module
Handles the export of scan results to various formats (JSON, CSV).
"""
import json
import csv
from typing import Dict, Any


def save_report(data: Dict[str, Any], filename: str) -> None:
    """
    Saves the scan data to a file. Format is inferred from the extension.

    Args:
        data: The dictionary containing scan results.
        filename: The path to save the file to.
    """
    if filename.lower().endswith(".json"):
        _save_json(data, filename)
    elif filename.lower().endswith(".csv"):
        _save_csv(data, filename)
    else:
        # Default to JSON if unknown or no extension
        if not filename.endswith("."):
            filename += ".json"
        _save_json(data, filename)


def _save_json(data: Dict[str, Any], filename: str) -> None:
    """Saves data as JSON."""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Report saved to {filename}")
    except IOError as e:
        print(f"[!] Error saving JSON report: {e}")


def _sanitize_csv_cell(cell_data: Any) -> Any:
    """
    Sanitizes data to prevent CSV Injection (Formula Injection).
    Prepends a single quote if the data starts with =, +, -, or @.
    Also handles values that might contain injection characters.
    """
    if isinstance(cell_data, str):
        # Check if it starts with injection characters
        if cell_data.startswith(("=", "+", "-", "@")):
            return f"'{cell_data}"
    return cell_data


def _save_csv(data: Dict[str, Any], filename: str) -> None:
    """Saves flat data as CSV. Flattens the hierarchical structure."""
    try:
        flat_rows = []

        # We'll focus on the 'hosts' list for the main CSV content

        for host in data.get("hosts", []):
            ip = host.get("ip")
            mac = host.get("mac", "")

            # If services found, create a row for each service
            services = host.get("services", [])
            if services:
                for svc in services:
                    flat_rows.append({
                        "ip": _sanitize_csv_cell(ip),
                        "mac": _sanitize_csv_cell(mac),
                        "port": svc.get("port"),
                        "url": _sanitize_csv_cell(svc.get("url")),
                        "status": svc.get("status"),
                        "fingerprint": _sanitize_csv_cell(svc.get("fingerprint")),
                        "type": "Web Service"
                    })
            else:
                # Just the host info
                flat_rows.append({
                    "ip": _sanitize_csv_cell(ip),
                    "mac": _sanitize_csv_cell(mac),
                    "port": "",
                    "url": "",
                    "status": "",
                    "fingerprint": "",
                    "type": "Host Only"
                })

        if not flat_rows:
            print("[!] No data to write to CSV.")
            return

        keys = flat_rows[0].keys()
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(flat_rows)
        print(f"[+] Report saved to {filename}")

    except IOError as e:
        print(f"[!] Error saving CSV report: {e}")
