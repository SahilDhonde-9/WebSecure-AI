from flask import Flask, render_template, request, jsonify
import socket
import ssl
import sqlite3
import hashlib
import datetime
import http.client

app = Flask(__name__)
DATABASE = 'scan_history.db'
FEATURE_HEADERS = [
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'content-security-policy',
    'referrer-policy'
]


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            scan_time TEXT,
            score INTEGER,
            risk TEXT,
            ssl_status TEXT,
            dns_address TEXT,
            headers TEXT,
            whois TEXT,
            summary TEXT
        )'''
    )
    conn.commit()
    conn.close()


def normalize_target(value):
    if not value:
        return ''
    target = value.strip()
    for prefix in ('http://', 'https://'):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split('/')[0]


def get_dns_info(target):
    try:
        host, aliases, ips = socket.gethostbyname_ex(target)
        return {
            'ok': True,
            'address': ips[0] if ips else host,
            'all_ips': ips
        }
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}


def get_ssl_info(target):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                cert = tls_sock.getpeercert()
                expires = cert.get('notAfter')
                days_left = None
                if expires:
                    try:
                        expires_dt = datetime.datetime.strptime(expires, '%b %d %H:%M:%S %Y %Z')
                        days_left = max(0, (expires_dt - datetime.datetime.utcnow()).days)
                    except ValueError:
                        days_left = None
                subject = next((x[0][1] for x in cert.get('subject', ()) if x[0][0] == 'commonName'), '')
                issuer = next((x[0][1] for x in cert.get('issuer', ()) if x[0][0] == 'organizationName'), '')
                return {
                    'ok': True,
                    'subject': subject or target,
                    'issuer': issuer or 'Unknown',
                    'expires': expires or 'Unknown',
                    'days_left': days_left
                }
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}


def get_security_headers(target):
    try:
        conn = http.client.HTTPSConnection(target, timeout=6)
        conn.request('HEAD', '/')
        response = conn.getresponse()
        raw_headers = {k.lower(): v for k, v in response.getheaders()}
        conn.close()
        found = [name for name in FEATURE_HEADERS if name in raw_headers]
        missing = [name for name in FEATURE_HEADERS if name not in raw_headers]
        return {
            'ok': True,
            'status': response.status,
            'found': found,
            'missing': missing,
            'headers': {name: raw_headers.get(name, '') for name in found}
        }
    except Exception as exc:
        return {'ok': False, 'error': str(exc), 'found': [], 'missing': FEATURE_HEADERS}


def get_whois_info(target):
    try:
        server = 'whois.iana.org'
        with socket.create_connection((server, 43), timeout=6) as sock:
            sock.sendall((target + '\r\n').encode())
            raw = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
        text = raw.decode(errors='ignore').strip()
        return text[:1200] if text else 'No WHOIS response available.'
    except Exception as exc:
        return f'WHOIS lookup failed: {exc}'


def check_common_ports(target):
    ports = [22, 80, 443, 21, 3389]
    results = {'open': [], 'closed': []}
    for port in ports:
        try:
            with socket.create_connection((target, port), timeout=1.0):
                results['open'].append(port)
        except Exception:
            results['closed'].append(port)
    return results


def calculate_score(dns_ok, ssl_ok, header_info):
    score = 40 if dns_ok else 0
    score += 30 if ssl_ok else 0
    score += 10 if 'strict-transport-security' in header_info.get('found', []) else 0
    score += 10 if 'x-frame-options' in header_info.get('found', []) else 0
    score += 10 if 'x-content-type-options' in header_info.get('found', []) else 0
    score += 5 if 'content-security-policy' in header_info.get('found', []) else 0
    score += 5 if 'referrer-policy' in header_info.get('found', []) else 0
    return min(max(score, 0), 100)


def record_scan(target, score, risk, ssl_status, dns_address, headers, whois, summary):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO history (target, scan_time, score, risk, ssl_status, dns_address, headers, whois, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (target, datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'), score, risk, ssl_status, dns_address, headers, whois, summary)
    )
    conn.commit()
    conn.close()


def build_recommendations(results):
    recs = []
    if not results['dns']['ok']:
        recs.append('Check the domain spelling and verify it resolves in DNS.')
    if not results['ssl']['ok']:
        recs.append('Enable a valid SSL certificate and serve content over HTTPS.')
    if results['ssl'].get('days_left') is not None and results['ssl']['days_left'] < 30:
        recs.append('Renew the certificate soon; it expires in less than 30 days.')
    for header in results['headers'].get('missing', []):
        if header == 'strict-transport-security':
            recs.append('Add Strict-Transport-Security to enforce HTTPS connections.')
        elif header == 'x-frame-options':
            recs.append('Add X-Frame-Options to reduce clickjacking risk.')
        elif header == 'x-content-type-options':
            recs.append('Add X-Content-Type-Options to prevent MIME sniffing.')
        elif header == 'content-security-policy':
            recs.append('Add a Content-Security-Policy header to harden browser behavior.')
        elif header == 'referrer-policy':
            recs.append('Add a Referrer-Policy header to improve privacy.')

    if not recs:
        recs.append('Your site looks solid. Keep monitoring certificates and security header coverage.')
    return recs[:6]


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/features')
def features_page():
    return render_template('features.html')


@app.route('/scan-summary')
def scan_summary_page():
    return render_template('scan_summary.html')


@app.route('/manual-toolbox')
def manual_toolbox_page():
    return render_template('toolbox.html')


@app.route('/run-scan', methods=['POST'])
def run_scan():
    data = request.json
    target_raw = data.get('target', '')
    target = normalize_target(target_raw)
    if not target:
        return jsonify({'status': 'error', 'message': 'Please enter a valid website or domain.'}), 400

    dns_result = get_dns_info(target)
    ssl_result = get_ssl_info(target)
    header_result = get_security_headers(target) if ssl_result['ok'] else {'ok': False, 'error': 'HTTPS check failed; security headers unavailable.', 'found': [], 'missing': FEATURE_HEADERS}
    whois_result = get_whois_info(target)

    score = calculate_score(dns_result['ok'], ssl_result['ok'], header_result)
    risk = 'Low' if score >= 80 else 'Medium' if score >= 55 else 'High'
    summary = f"DNS={'OK' if dns_result['ok'] else 'FAIL'} | SSL={'OK' if ssl_result['ok'] else 'FAIL'} | Score={score} | Risk={risk}"

    record_scan(
        target,
        score,
        risk,
        'Valid' if ssl_result['ok'] else 'Invalid',
        dns_result.get('address', 'N/A'),
        ', '.join(header_result.get('found', [])),
        whois_result,
        summary
    )

    recommendations = build_recommendations({'dns': dns_result, 'ssl': ssl_result, 'headers': header_result})

    return jsonify({
        'status': 'success',
        'target': target,
        'dns': dns_result,
        'ssl': ssl_result,
        'headers': header_result,
        'whois': whois_result,
        'score': score,
        'risk': risk,
        'recommendations': recommendations,
        'summary': summary
    })


@app.route('/scan-history', methods=['GET'])
def scan_history():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT target, scan_time, score, risk, ssl_status, dns_address FROM history ORDER BY id DESC LIMIT 10')
    rows = cursor.fetchall()
    conn.close()
    history = [
        {
            'target': row[0],
            'time': row[1],
            'score': row[2],
            'risk': row[3],
            'ssl_status': row[4],
            'dns_address': row[5]
        }
        for row in rows
    ]
    return jsonify({'history': history})


@app.route('/port-check', methods=['POST'])
def port_check():
    data = request.json
    target_raw = data.get('target', '')
    target = normalize_target(target_raw)
    if not target:
        return jsonify({'status': 'error', 'message': 'Please enter a valid website or domain for port check.'}), 400
    dns_result = get_dns_info(target)
    results = check_common_ports(target)
    summary = f"Open ports: {', '.join(str(p) for p in results['open']) or 'None'}"
    return jsonify({
        'status': 'success',
        'target': target,
        'open_ports': results['open'],
        'closed_ports': results['closed'],
        'dns_address': dns_result.get('address', 'N/A'),
        'dns_ok': dns_result.get('ok', False),
        'summary': summary
    })


@app.route('/run-module', methods=['POST'])
def run_module():
    data = request.json
    module_id = data.get('module_id')
    user_input = data.get('input_val', '').strip()
    extra_input = data.get('extra_val', '').strip()

    result = {'status': 'info', 'message': ''}

    if module_id == '2':
        if not user_input:
            user_input = 'localhost'
        try:
            ip = socket.gethostbyname(user_input)
            result = {'status': 'success', 'message': f'Target Domain: {user_input}<br>[+] Resolved IP: {ip}'}
        except socket.gaierror:
            result = {'status': 'error', 'message': f'Could not resolve host: {user_input}'}

    elif module_id == '5':
        software = user_input.lower()
        version = extra_input
        mock_db = {'apache': '2.4.49', 'openssh': '8.4p1'}

        if software in mock_db:
            if version <= mock_db[software]:
                result = {'status': 'warn', 'message': f'[WARNING] {software} v{version} may be outdated.<br>Known vulnerable baseline: <= v{mock_db[software]}'}
            else:
                result = {'status': 'success', 'message': f'[+] {software} v{version} appears up to date against local definitions.'}
        else:
            result = {'status': 'error', 'message': f"Software '{software}' signature not found in database."}

    elif module_id == '20':
        if not user_input:
            result = {'status': 'error', 'message': 'Please enter text to hash.'}
        else:
            sha256_hash = hashlib.sha256(user_input.encode()).hexdigest()
            result = {'status': 'success', 'message': f"SHA-256 Digest:<br><strong style='word-break: break-all;'>{sha256_hash}</strong>"}

    return jsonify(result)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
