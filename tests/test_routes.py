import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from app import app as flask_app

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as c:
        yield c

def test_index_returns_200(client):
    resp = client.get('/')
    assert resp.status_code == 200

def test_scan_returns_scan_id(client):
    resp = client.post('/scan', json={"input": "google.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "scan_id" in data
    assert re.match(r'^[0-9a-f\-]{36}$', data["scan_id"])

def test_scan_rejects_empty_input(client):
    resp = client.post('/scan', json={"input": ""})
    assert resp.status_code == 400

def test_stream_404_unknown_scan(client):
    resp = client.get('/stream/does-not-exist')
    assert resp.status_code == 404
