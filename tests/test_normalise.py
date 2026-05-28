import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import normalise_input, is_domain

def test_strips_https():
    assert normalise_input("https://google.com") == "google.com"

def test_strips_http():
    assert normalise_input("http://google.com") == "google.com"

def test_strips_www():
    assert normalise_input("www.google.com") == "google.com"

def test_strips_https_www_slash():
    assert normalise_input("https://www.google.com/") == "google.com"

def test_strips_trailing_slash():
    assert normalise_input("google.com/") == "google.com"

def test_lowercases():
    assert normalise_input("Google.COM") == "google.com"

def test_passes_through_bare_domain():
    assert normalise_input("google.com") == "google.com"

def test_is_domain_true():
    assert is_domain("google.com") is True

def test_is_domain_false_spaces():
    assert is_domain("Google Inc") is False

def test_is_domain_false_no_dot():
    assert is_domain("google") is False
