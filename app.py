import uuid
import json
import os
import re

from flask import Flask, request, jsonify, Response, render_template, stream_with_context
import whois as whois_lib
import dns.resolver
import requests as http
import anthropic

app = Flask(__name__)
scans = {}  # scan_id -> {"input": str, "data": dict}
_client = None

def get_client():
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client

def normalise_input(raw: str) -> str:
    s = raw.strip().lower()
    s = re.sub(r'^https?://', '', s)
    s = re.sub(r'^www\.', '', s)
    s = s.rstrip('/')
    return s

def is_domain(s: str) -> bool:
    return '.' in s and ' ' not in s

def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

def run_scan(raw_input: str, data: dict):
    yield sse("done", {})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    body = request.get_json(force=True)
    raw = (body.get('input') or '').strip()
    if not raw:
        return jsonify({"error": "input is required"}), 400
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {"input": raw, "data": {}}
    return jsonify({"scan_id": scan_id})

@app.route('/stream/<scan_id>')
def stream(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404

    def generate():
        yield from run_scan(scan["input"], scan["data"])

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)
