#!/usr/bin/env python3
"""
Web server for Bitcoin transaction analyzer
Provides API endpoints and web UI
"""

import sys
import os
import json
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

# Add app directory to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from main import analyze_transaction, error_response

app = Flask(__name__)
CORS(app)

# HTML template for the UI
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Bitcoin Transaction Analyzer</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 40px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            margin-bottom: 20px;
        }
        
        .input-section {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            font-weight: 600;
            margin-bottom: 8px;
            color: #333;
        }
        
        textarea {
            width: 100%;
            min-height: 150px;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            resize: vertical;
        }
        
        textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 14px 32px;
            font-size: 16px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        button:hover {
            transform: translateY(-2px);
        }
        
        button:active {
            transform: translateY(0);
        }
        
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        
        .result-section {
            margin-top: 30px;
        }
        
        .result-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .result-header h2 {
            color: #333;
        }
        
        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
        }
        
        .status-success {
            background: #10b981;
            color: white;
        }
        
        .status-error {
            background: #ef4444;
            color: white;
        }
        
        .json-output {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.6;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .summary-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        
        .summary-item label {
            font-size: 12px;
            color: #666;
            margin-bottom: 5px;
        }
        
        .summary-item .value {
            font-size: 18px;
            font-weight: 600;
            color: #333;
        }
        
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 12px;
            margin: 15px 0;
        }
        
        .warning-box strong {
            color: #856404;
        }
        
        .example-btn {
            background: #6c757d;
            margin-left: 10px;
            padding: 8px 16px;
            font-size: 14px;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        
        .loading.active {
            display: block;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⛓️ Bitcoin Transaction Analyzer</h1>
            <p>Analyze Bitcoin transactions and understand what's happening under the hood</p>
        </div>
        
        <div class="card">
            <div class="input-section">
                <label for="fixture">Paste Transaction Fixture JSON:</label>
                <textarea id="fixture" placeholder='Paste your fixture JSON here, e.g.:
{
  "network": "mainnet",
  "raw_tx": "0200000001...",
  "prevouts": [...]
}'></textarea>
            </div>
            
            <button onclick="analyzeTransaction()" id="analyzeBtn">
                🔍 Analyze Transaction
            </button>
            <button class="example-btn" onclick="loadExample()">
                📝 Load Example
            </button>
        </div>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p style="margin-top: 10px; color: white;">Analyzing transaction...</p>
        </div>
        
        <div id="results" style="display: none;">
            <div class="card">
                <div class="result-header">
                    <h2>Analysis Results</h2>
                    <span class="status-badge" id="statusBadge"></span>
                </div>
                
                <div id="summary" style="display: none;">
                    <div class="summary-grid">
                        <div class="summary-item">
                            <label>Transaction ID</label>
                            <div class="value" id="txid" style="font-size: 14px; word-break: break-all;"></div>
                        </div>
                        <div class="summary-item">
                            <label>Fee</label>
                            <div class="value" id="fee"></div>
                        </div>
                        <div class="summary-item">
                            <label>Fee Rate</label>
                            <div class="value" id="feeRate"></div>
                        </div>
                        <div class="summary-item">
                            <label>Size</label>
                            <div class="value" id="size"></div>
                        </div>
                        <div class="summary-item">
                            <label>Inputs</label>
                            <div class="value" id="inputs"></div>
                        </div>
                        <div class="summary-item">
                            <label>Outputs</label>
                            <div class="value" id="outputs"></div>
                        </div>
                    </div>
                    
                    <div id="warningsBox" style="display: none;" class="warning-box">
                        <strong>⚠️ Warnings:</strong>
                        <ul id="warningsList" style="margin-left: 20px; margin-top: 8px;"></ul>
                    </div>
                </div>
                
                <div class="result-section">
                    <h3 style="margin-bottom: 10px;">Full JSON Output:</h3>
                    <pre class="json-output" id="jsonOutput"></pre>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const exampleFixture = {
            "network": "mainnet",
            "raw_tx": "0200000001a3b9e5f6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f40000000000ffffffff0200e1f505000000001976a914deadbeefdeadbeefdeadbeefdeadbeefdeadbeef88ac80969800000000001976a914cafebabecafebabecafebabecafebabecafebabe88ac00000000",
            "prevouts": [
                {
                    "txid": "f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7f6e5b9a3",
                    "vout": 0,
                    "value_sats": 110000000,
                    "script_pubkey_hex": "76a914abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd88ac"
                }
            ]
        };
        
        function loadExample() {
            document.getElementById('fixture').value = JSON.stringify(exampleFixture, null, 2);
        }
        
        async function analyzeTransaction() {
            const fixtureText = document.getElementById('fixture').value.trim();
            
            if (!fixtureText) {
                alert('Please paste a fixture JSON');
                return;
            }
            
            let fixture;
            try {
                fixture = JSON.parse(fixtureText);
            } catch (e) {
                alert('Invalid JSON: ' + e.message);
                return;
            }
            
            // Show loading
            document.getElementById('loading').classList.add('active');
            document.getElementById('results').style.display = 'none';
            document.getElementById('analyzeBtn').disabled = true;
            
            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(fixture)
                });
                
                const result = await response.json();
                
                // Hide loading
                document.getElementById('loading').classList.remove('active');
                document.getElementById('analyzeBtn').disabled = false;
                
                // Show results
                document.getElementById('results').style.display = 'block';
                document.getElementById('jsonOutput').textContent = JSON.stringify(result, null, 2);
                
                // Update status badge
                const statusBadge = document.getElementById('statusBadge');
                if (result.ok) {
                    statusBadge.textContent = '✓ Success';
                    statusBadge.className = 'status-badge status-success';
                    
                    // Show summary
                    document.getElementById('summary').style.display = 'block';
                    document.getElementById('txid').textContent = result.txid || 'N/A';
                    document.getElementById('fee').textContent = (result.fee_sats || 0).toLocaleString() + ' sats';
                    document.getElementById('feeRate').textContent = (result.fee_rate_sat_vb || 0) + ' sat/vB';
                    document.getElementById('size').textContent = (result.vbytes || 0) + ' vBytes';
                    document.getElementById('inputs').textContent = (result.vin || []).length;
                    document.getElementById('outputs').textContent = (result.vout || []).length;
                    
                    // Show warnings if any
                    if (result.warnings && result.warnings.length > 0) {
                        document.getElementById('warningsBox').style.display = 'block';
                        const warningsList = document.getElementById('warningsList');
                        warningsList.innerHTML = '';
                        result.warnings.forEach(w => {
                            const li = document.createElement('li');
                            li.textContent = w;
                            warningsList.appendChild(li);
                        });
                    } else {
                        document.getElementById('warningsBox').style.display = 'none';
                    }
                } else {
                    statusBadge.textContent = '✗ Error';
                    statusBadge.className = 'status-badge status-error';
                    document.getElementById('summary').style.display = 'none';
                }
            } catch (error) {
                document.getElementById('loading').classList.remove('active');
                document.getElementById('analyzeBtn').disabled = false;
                alert('Error: ' + error.message);
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Serve the main web UI"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"ok": True}), 200

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyze a transaction from fixture JSON"""
    try:
        fixture = request.get_json()
        
        if not fixture:
            return jsonify(error_response('INVALID_INPUT', 'No JSON body provided')), 400
        
        # Validate required fields
        if 'raw_tx' not in fixture:
            return jsonify(error_response('MISSING_FIELD', 'Missing required field: raw_tx')), 400
        
        if 'prevouts' not in fixture:
            return jsonify(error_response('MISSING_FIELD', 'Missing required field: prevouts')), 400
        
        # Write fixture to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(fixture, f)
            temp_path = f.name
        
        # Analyze transaction
        result = analyze_transaction(temp_path)
        
        # Clean up temp file
        os.unlink(temp_path)
        
        return jsonify(result), 200 if result.get('ok') else 400
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify(error_response('SERVER_ERROR', str(e))), 500
if __name__ == '__main__':
    import os
    import logging

    port = int(os.environ.get("PORT", 3000))

    # Disable Werkzeug logs
    logging.getLogger('werkzeug').setLevel(logging.ERROR)

    # Disable Flask startup banner
    import click
    click.echo = lambda *args, **kwargs: None

    app.run(host="127.0.0.1", port=port, debug=False)