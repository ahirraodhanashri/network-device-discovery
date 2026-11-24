"""Network Device Discovery Tool - Flask API + static frontend.

Run:   python app.py        then open  http://127.0.0.1:5000
"""
import csv
import io
import json
import os
import threading
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

import analysis
import db
import discovery
import demo as demo_module
import netutils
import packets

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app = Flask(__name__, static_folder=None)

# The frontend is served by Flask itself, so CORS is only needed if you host it elsewhere.
try:
    from flask_cors import CORS
    CORS(app, resources={r"/api/*": {"origins": os.environ.get("FRONTEND_ORIGIN", "http://127.0.0.1:5000")}})
except ImportError:
    pass

_scan_lock = threading.Lock()  # one scan at a time: scans are slow and generate traffic


def error(message, status=400):
    return jsonify({"error": message}), status


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


# --------------------------------------------------------------------------- #
# Frontend
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


# --------------------------------------------------------------------------- #
# Info endpoints
# --------------------------------------------------------------------------- #
@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok", "app": "Network Device Discovery Tool",
        "scapy_available": discovery.SCAPY_AVAILABLE,
        "ping_available": netutils.ping_available(),
        "local_ip": netutils.get_local_ip(),
        "gateway_ip": netutils.get_default_gateway(),
        "demo_variants": demo_module.VARIANTS,
    })


@app.get("/api/subnet-info")
def subnet_info():
    try:
        network = netutils.parse_cidr(request.args.get("cidr", ""))
    except ValueError as exc:
        return error(str(exc))
    return jsonify(netutils.subnet_info(network))


@app.get("/api/packet/arp")
def arp_packet():
    """Build (not send) an ARP request so students can inspect every byte."""
    target = request.args.get("target", "192.168.1.1")
    src_ip = request.args.get("src_ip") or netutils.get_local_ip() or "192.168.1.50"
    src_mac = request.args.get("src_mac") or netutils.get_local_mac() or "aa:bb:cc:dd:ee:ff"
    try:
        frame = packets.build_arp_request(src_mac, src_ip, target)
    except ValueError as exc:
        return error(f"Invalid input: {exc}")
    return jsonify({
        "description": f"ARP request: who has {target}? Tell {src_ip}",
        "length_bytes": len(frame),
        "note": "This frame is only built for display; it is never transmitted. "
                "The NIC pads Ethernet frames to 60 bytes on the wire.",
        "fields": packets.explain_frame(frame),
        "hexdump": packets.hexdump(frame),
    })


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
def _read_scan_request(body):
    """Validate the POST body. Returns (network, methods, ports, demo_variant)."""
    network = netutils.parse_scan_subnet(body.get("subnet", ""))
    methods = body.get("methods") or ["arp"]
    if not isinstance(methods, list) or not set(methods) <= set(discovery.VALID_METHODS):
        raise ValueError("methods must be a list containing 'arp', 'icmp' and/or 'tcp'.")
    ports = netutils.parse_ports(body.get("ports"))
    variant = body.get("demo") or None
    if variant and variant not in demo_module.VARIANTS:
        raise ValueError(f"Unknown demo variant '{variant}'.")
    return network, methods, ports, variant


@app.post("/api/scans")
def start_scan():
    body = request.get_json(silent=True) or {}
    try:
        network, methods, ports, variant = _read_scan_request(body)
    except ValueError as exc:
        return error(str(exc))

    # Demo scans send no packets, so only real scans need the authorization tick.
    if not variant and body.get("authorized") is not True:
        return error("Confirm that you own or have permission to scan this network.", 403)

    if not _scan_lock.acquire(blocking=False):
        return error("Another scan is already running. Wait for it to finish.", 429)
    try:
        label = "+".join(m.upper() for m in discovery.VALID_METHODS if m in methods)
        if variant:
            label += " (DEMO)"
        try:
            result = discovery.run_discovery(network, methods, ports, variant)
        except ValueError as exc:
            return error(str(exc))
        except Exception as exc:  # scan failed (permissions, missing driver...): record it
            scan_id = db.save_scan(str(network), label, "failed", error=str(exc), demo_variant=variant)
            return jsonify({"scan_id": scan_id, "subnet": str(network), "status": "failed", "error": str(exc)}), 500

        scan_id = db.save_scan(str(network), label, "completed", result, demo_variant=variant)
        previous_id = db.previous_scan_id(str(network), bool(variant), scan_id)
        changes = None
        if previous_id:
            changes = analysis.compare_scans(db.get_devices(previous_id), result["devices"], result["gateway_ip"])
            changes["previous_scan_id"] = previous_id
        return jsonify({
            "scan_id": scan_id, "subnet": str(network), "method": label, "status": "completed",
            "is_demo": bool(variant), "device_count": len(result["devices"]),
            "devices": result["devices"], "gateway_ip": result["gateway_ip"],
            "anomalies": result["anomalies"], "method_comparison": result["method_comparison"],
            "notes": result["notes"], "changes_since_previous": changes,
        })
    finally:
        _scan_lock.release()


@app.get("/api/scans")
def list_scans():
    return jsonify(db.list_scans())


@app.get("/api/scans/compare")
def compare_scans():
    try:
        old_id, new_id = int(request.args["old"]), int(request.args["new"])
    except (KeyError, ValueError):
        return error("Provide numeric old and new scan IDs.")
    old, new = db.get_scan(old_id), db.get_scan(new_id)
    if not old or not new:
        return error("Scan not found", 404)
    result = analysis.compare_scans(old["devices"], new["devices"], new.get("gateway_ip"))
    result.update({"old_scan_id": old_id, "new_scan_id": new_id,
                   "mixed_sources": old["is_demo"] != new["is_demo"]})
    return jsonify(result)


@app.get("/api/scans/<int:scan_id>")
def get_scan(scan_id):
    scan = db.get_scan(scan_id)
    return jsonify(scan) if scan else error("Scan not found", 404)


@app.delete("/api/scans/<int:scan_id>")
def delete_scan(scan_id):
    return jsonify({"deleted": scan_id}) if db.delete_scan(scan_id) else error("Scan not found", 404)


def _csv_safe(value):
    """Stop spreadsheet formula injection: hostnames come from the network and are untrusted."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@app.get("/api/scans/<int:scan_id>/export.csv")
def export_csv(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return error("Scan not found", 404)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["ip", "mac", "vendor", "hostname", "found_by", "rtt_ms", "ttl", "os_hint",
                     "open_ports", "is_gateway"])
    for d in scan["devices"]:
        writer.writerow([_csv_safe(v) for v in (
            d["ip"], d["mac"], d["vendor"], d["hostname"], "+".join(d["methods"]), d["rtt_ms"], d["ttl"],
            d["os_hint"], " ".join(f"{p['port']}/{p['service']}" for p in d["open_ports"]),
            "yes" if d["is_gateway"] else "")])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.csv"})


db.init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
