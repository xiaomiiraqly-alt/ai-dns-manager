"""Explicit opt-in Gemini generation probe; never writes credentials to reports."""
import http.client
import ipaddress
import json
import re
import ssl
from .transports import PinnedHTTPS

HOST = 'generativelanguage.googleapis.com'


def classify(status, data):
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        return 'INVALID_RESPONSE'
    error = data.get('error', {})
    if not isinstance(error, dict):
        error = {'message': str(error)}
    message = str(error.get('message', '')).lower()
    if 'location' in message and ('not supported' in message or 'not available' in message):
        return 'REGION_BLOCKED'
    if status in (401, 403) or 'api key' in message or 'api_key' in message:
        return 'AUTH_OR_PERMISSION'
    if status == 429:
        return 'QUOTA_OR_RATE_LIMIT'
    if status == 404 or ('model' in message and status == 400):
        return 'MODEL_OR_CONFIGURATION'
    if status >= 500:
        return 'UPSTREAM_ERROR'
    if status == 200:
        choices = data.get('choices', [])
        if choices and isinstance(choices[0], dict) and isinstance(choices[0].get('message'), dict):
            content = choices[0]['message'].get('content')
            if isinstance(content, str) and content.strip():
                return 'GENERATION_OK'
        return 'EMPTY_GENERATION'
    return 'REQUEST_REJECTED'


def probe(ip, key, model, timeout=20):
    if not ipaddress.ip_address(ip).is_global:
        return {'category': 'UNSAFE_ADDRESS', 'generation_ok': False}
    if not key or not model or any(c in key for c in '\r\n'):
        raise ValueError('Missing or invalid Gemini credentials/model')
    conn = PinnedHTTPS(HOST, ip, 443, timeout)
    try:
        payload = json.dumps({'model': model,
            'messages': [{'role': 'user', 'content': 'Reply with the single word OK.'}],
            'max_tokens': 256}).encode()
        conn.request('POST', '/v1beta/openai/chat/completions', body=payload, headers={
            'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json', 'Connection': 'close'})
        response = conn.getresponse()
        raw = response.read(65537)
        if len(raw) > 65536:
            return {'category': 'INVALID_RESPONSE', 'generation_ok': False, 'http_status': response.status}
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        category = classify(response.status, data)
        return {'category': category, 'generation_ok': category == 'GENERATION_OK', 'http_status': response.status}
    except ssl.SSLError:
        return {'category': 'TLS_ERROR', 'generation_ok': False}
    except (OSError, ValueError, http.client.HTTPException):
        return {'category': 'NETWORK_ERROR', 'generation_ok': False}
    finally:
        conn.close()
