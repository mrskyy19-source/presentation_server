from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import os
import re

app = Flask(__name__)
CORS(app)

# --- VULNERABILITY DETECTION RULES (SAST) ---
# These regex patterns look for the dangerous code snippets from the cheatsheet
RULES = [
    {
        "id": "NOSQL-INJECTION-001",
        "pattern": r"(req\.body\.username|req\.body\.password|req\.query)",
        "context_must_exist": ["findOne", "find", "update"],
        "severity": "CRITICAL",
        "description": "Potential NoSQL Injection. User input is passed directly to a database query without sanitization."
    },
    {
        "id": "JWT-CONFUSION-002",
        "pattern": r"jwt\.verify\([^,]+,\s*[^,]+(?!,\s*{.*algorithms)",
        "severity": "HIGH",
        "description": "Unsafe JWT Verification. No 'algorithms' array specified, making it vulnerable to RS256/HS256 algorithm confusion attacks."
    },
    {
        "id": "PROTOTYPE-POLL-003",
        "pattern": r"(__proto__|prototype)\s*[\[=]",
        "severity": "HIGH",
        "description": "Potential Prototype Pollution. Direct modification of object prototypes detected."
    },
    {
        "id": "UNSAFE-MERGE-004",
        "pattern": r"(merge\(|extend\(|assign\()",
        "severity": "MEDIUM",
        "description": "Potential Prototype Pollution. Deep merge/extend functions can be exploited if user input is not sanitized first."
    }
]

def scan_code(content):
    findings = []
    lines = content.splitlines()
    
    for i, line in enumerate(lines):
        for rule in RULES:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                # If the rule requires specific context (like MongoDB functions)
                if "context_must_exist" in rule:
                    if not any(ctx in content for ctx in rule["context_must_exist"]):
                        continue
                
                findings.append({
                    "line": i + 1,
                    "code": line.strip(),
                    "vulnerability": rule["id"],
                    "severity": rule["severity"],
                    "description": rule["description"]
                })
    return findings

@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SAST Code Auditor</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0c29; min-height: 100vh; color: white; }
            .container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }
            .header { text-align: center; margin-bottom: 40px; }
            .header h1 { font-size: 2.5em; margin-bottom: 10px; color: #00f2ff; }
            .card { background: rgba(255,255,255,0.05); backdrop-filter: blur(10px); border-radius: 15px; padding: 30px; margin-bottom: 20px; border: 1px solid rgba(255,255,255,0.1); }
            .upload-area { border: 2px dashed rgba(255,255,255,0.3); border-radius: 10px; padding: 40px; text-align: center; cursor: pointer; transition: all 0.3s; }
            .upload-area:hover { border-color: #00f2ff; background: rgba(0,242,255,0.05); }
            input[type="file"] { display: none; }
            .btn { background: linear-gradient(45deg, #00f2ff, #0066ff); color: #000; border: none; padding: 12px 30px; border-radius: 25px; font-size: 16px; font-weight: bold; cursor: pointer; transition: transform 0.2s; margin: 10px; }
            .btn:hover { transform: scale(1.05); }
            #results { margin-top: 20px; }
            .vuln-item { background: rgba(220,53,69,0.1); padding: 15px; border-radius: 10px; margin: 10px 0; border-left: 4px solid #dc3545; }
            .safe-item { background: rgba(40,167,69,0.1); padding: 15px; border-radius: 10px; margin: 10px 0; border-left: 4px solid #28a745; }
            .badge { display: inline-block; padding: 5px 15px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }
            .crit { background: #dc3545; color: white; }
            .high { background: #ffc107; color: black; }
            .med { background: #fd7e14; color: white; }
            .loading { display: none; text-align: center; padding: 20px; }
            .spinner { border: 4px solid rgba(255,255,255,0.1); border-top: 4px solid #00f2ff; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            pre { background: #1e1e1e; padding: 10px; border-radius: 5px; margin-top: 5px; overflow-x: auto; font-size: 0.9em; color: #d4d4d4; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ SAST Code Auditor</h1>
                <p>High-Payout Vulnerability Scanner for Node.js & API Source Code</p>
            </div>

            <div class="card">
                <h2>📁 Upload Source Code for Scanning</h2>
                <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                    <div style="font-size: 3em; margin-bottom: 10px;">⬆️</div>
                    <p>Click to upload your application source files</p>
                    <p style="font-size: 0.8em; color: rgba(255,255,255,0.5);">Accepts .js, .ts, .py, .txt, .json</p>
                </div>
                <input type="file" id="fileInput" accept=".js,.ts,.py,.txt,.json" onchange="handleFileSelect(event)">

                <button class="btn" onclick="startScan()">🚀 Start Security Audit</button>

                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <p>🔍 Scanning for zero-day logic flaws...</p>
                </div>
            </div>

            <div id="results"></div>
        </div>

        <script>
            let selectedFile = null;

            function handleFileSelect(event) {
                selectedFile = event.target.files[0];
                if (selectedFile) {
                    document.querySelector('.upload-area').innerHTML =
                        `<div style="font-size: 3em; margin-bottom: 10px;">✅</div>
                         <p><strong>${selectedFile.name}</strong></p>
                         <p style="font-size: 0.8em; color: rgba(255,255,255,0.5);">${(selectedFile.size / 1024).toFixed(2)} KB</p>`;
                }
            }

            async function startScan() {
                if (!selectedFile) {
                    alert('Please select a source file first!');
                    return;
                }

                document.getElementById('loading').style.display = 'block';
                document.getElementById('results').innerHTML = '';

                const formData = new FormData();
                formData.append('file', selectedFile);

                try {
                    const response = await fetch('/scan', { method: 'POST', body: formData });
                    const data = await response.json();
                    displayResults(data);
                } catch (error) {
                    document.getElementById('results').innerHTML = `<div class="card" style="color: #dc3545;">❌ Error: ${error.message}</div>`;
                } finally {
                    document.getElementById('loading').style.display = 'none';
                }
            }

            function displayResults(data) {
                const findingsHtml = data.findings.length > 0 
                    ? data.findings.map(f =>
                        `<div class="vuln-item">
                            <span class="badge ${f.severity.toLowerCase()}">${f.severity}</span> 
                            <strong>${f.vulnerability}</strong><br>
                            <small style="color: #aaa;">Line ${f.line}:</small>
                            <pre>${f.code}</pre>
                            <p style="margin-top:10px; font-size:0.9em;">${f.description}</p>
                        </div>`
                    ).join('')
                    : `<div class="safe-item">✅ No known high-risk vulnerability patterns detected. Code looks clean!</div>`;

                document.getElementById('results').innerHTML = `
                    <div class="card">
                        <h2>📊 Audit Report for ${data.file}</h2>
                        <p><strong>Audit ID:</strong> ${data.audit_id}</p>

                        <h3 style="margin-top: 20px; color: #00f2ff;">Findings (${data.findings.length})</h3>
                        ${findingsHtml}
                        
                        <div style="margin-top: 20px; font-size: 0.8em; color: #666; border-top: 1px solid #333; padding-top: 10px;">
                            🔒 Integrity Hash: ${data.integrity_hash}
                        </div>
                    </div>
                `;
            }
        </script>
    </body>
    </html>
    '''

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    
    # Prevent path traversal Attack: Sanitize filename safely
    safe_filename = os.path.basename(file.filename)
    
    try:
        # Read file content securely
        content = file.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return jsonify({"error": "Could not read file"}), 400

    # Run the static analysis
    findings = scan_code(content)

    # Generate an immutable audit hash (like a blockchain TX, but functional)
    integrity_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()

    result = {
        "file": safe_filename,
        "audit_id": f"SAST-{os.urandom(4).hex().upper()}",
        "findings": findings,
        "integrity_hash": integrity_hash
    }

    return jsonify(result), 200

if __name__ == '__main__':
    # Run on localhost only for security during local freelance audits
    app.run(host='127.0.0.1', port=5000, debug=False)
