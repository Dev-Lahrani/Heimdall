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
