

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import json
import csv
import io
from datetime import datetime
import os

# Import detection engine components
# from detection_engine import HybridAttackDetector, AttackDatabase, PCAPProcessor

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend access

# Initialize components
# db = AttackDatabase('attack_detection.db')
# detector = HybridAttackDetector()
# pcap_processor = PCAPProcessor(detector)


# ==================== API ENDPOINTS ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })


@app.route('/api/detect', methods=['POST'])
def detect_url():
    """
    Detect attacks in a single URL
    
    Request body:
    {
        "url": "http://example.com/page?id=1",
        "method": "GET",
        "source_ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0..."
    }
    """
    try:
        data = request.get_json()
        
        if 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        # Perform detection
        detection = detector.detect(
            data['url'],
            data.get('method', 'GET')
        )
        
        # Add additional metadata
        detection['source_ip'] = data.get('source_ip', request.remote_addr)
        detection['user_agent'] = data.get('user_agent', request.headers.get('User-Agent'))
        detection['attack_type'] = detection['primary_attack']
        
        # Store in database
        record_id = db.insert_detection(detection)
        detection['id'] = record_id
        
        return jsonify(detection), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/detect/batch', methods=['POST'])
def detect_batch():
    """
    Detect attacks in multiple URLs
    
    Request body:
    {
        "urls": ["http://example.com/1", "http://example.com/2"],
        "source_ip": "192.168.1.100"
    }
    """
    try:
        data = request.get_json()
        
        if 'urls' not in data or not isinstance(data['urls'], list):
            return jsonify({'error': 'urls array is required'}), 400
        
        results = []
        source_ip = data.get('source_ip', request.remote_addr)
        
        for url in data['urls']:
            detection = detector.detect(url)
            detection['source_ip'] = source_ip
            detection['attack_type'] = detection['primary_attack']
            
            record_id = db.insert_detection(detection)
            detection['id'] = record_id
            results.append(detection)
        
        return jsonify({
            'total': len(results),
            'detections': results
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/attacks', methods=['GET'])
def get_attacks():
    """
    Query attack records with filters
    
    Query parameters:
    - attack_type: Filter by attack type
    - ip_range: Filter by IP range (e.g., "192.168")
    - status: "all", "successful", "attempt"
    - date_from: Start date (ISO format)
    - date_to: End date (ISO format)
    - limit: Maximum number of records (default: 100)
    """
    try:
        filters = {
            'attack_type': request.args.get('attack_type', 'all'),
            'ip_range': request.args.get('ip_range', ''),
            'status': request.args.get('status', 'all'),
            'date_from': request.args.get('date_from', ''),
            'date_to': request.args.get('date_to', '')
        }
        
        limit = int(request.args.get('limit', 100))
        
        results = db.query_attacks(filters)
        
        # Parse JSON fields
        for result in results:
            if result.get('all_detections'):
                result['all_detections'] = json.loads(result['all_detections'])
        
        return jsonify({
            'total': len(results),
            'filters': filters,
            'data': results[:limit]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """
    Get overall statistics
    """
    try:
        all_attacks = db.query_attacks()
        
        malicious = [a for a in all_attacks if a['attack_type'] != 'Benign']
        successful = [a for a in all_attacks if a['is_successful']]
        
        # Attack type distribution
        attack_types = {}
        for attack in malicious:
            attack_type = attack['attack_type']
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        # IP distribution
        ip_stats = {}
        for attack in malicious:
            ip = attack['source_ip']
            ip_stats[ip] = ip_stats.get(ip, 0) + 1
        
        # Top attacking IPs
        top_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Timeline data (attacks per day)
        timeline = {}
        for attack in malicious:
            date = attack['timestamp'].split('T')[0]
            timeline[date] = timeline.get(date, 0) + 1
        
        timeline_data = [{'date': k, 'count': v} for k, v in sorted(timeline.items())]
        
        return jsonify({
            'total_requests': len(all_attacks),
            'malicious_attempts': len(malicious),
            'successful_attacks': len(successful),
            'blocked_attacks': len(malicious) - len(successful),
            'attack_types': attack_types,
            'top_attacking_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
            'timeline': timeline_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/json', methods=['GET'])
def export_json():
    """Export filtered attack data as JSON"""
    try:
        filters = {
            'attack_type': request.args.get('attack_type', 'all'),
            'ip_range': request.args.get('ip_range', ''),
            'status': request.args.get('status', 'all'),
        }
        
        results = db.query_attacks(filters)
        
        # Parse JSON fields
        for result in results:
            if result.get('all_detections'):
                result['all_detections'] = json.loads(result['all_detections'])
        
        # Create JSON file
        output = io.BytesIO()
        output.write(json.dumps(results, indent=2).encode('utf-8'))
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'attack_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Export filtered attack data as CSV"""
    try:
        filters = {
            'attack_type': request.args.get('attack_type', 'all'),
            'ip_range': request.args.get('ip_range', ''),
            'status': request.args.get('status', 'all'),
        }
        
        results = db.query_attacks(filters)
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        headers = ['ID', 'Timestamp', 'Source IP', 'Attack Type', 'Confidence', 
                  'Status', 'Method', 'URL']
        writer.writerow(headers)
        
        # Write data
        for result in results:
            status = 'Successful' if result['is_successful'] else \
                    ('Attempt' if result['attack_type'] != 'Benign' else 'Benign')
            
            writer.writerow([
                result['id'],
                result['timestamp'],
                result['source_ip'],
                result['attack_type'],
                result['confidence'],
                status,
                result['method'],
                result['url']
            ])
        
        # Convert to bytes
        output_bytes = io.BytesIO()
        output_bytes.write(output.getvalue().encode('utf-8'))
        output_bytes.seek(0)
        
        return send_file(
            output_bytes,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'attack_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/pcap/upload', methods=['POST'])
def upload_pcap():
    """
    Upload and process PCAP file
    
    Expects multipart/form-data with 'file' field
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        if not file.filename.endswith(('.pcap', '.pcapng')):
            return jsonify({'error': 'Invalid file type. Must be .pcap or .pcapng'}), 400
        
        # Save file temporarily
        upload_folder = 'uploads'
        os.makedirs(upload_folder, exist_ok=True)
        
        filepath = os.path.join(upload_folder, file.filename)
        file.save(filepath)
        
        # Process PCAP
        results = pcap_processor.process_pcap(filepath)
        
        # Store detections in database
        for detection in results['detections']:
            detection['attack_type'] = detection['primary_attack']
            db.insert_detection(detection)
        
        # Clean up
        os.remove(filepath)
        
        return jsonify({
            'message': 'PCAP processed successfully',
            'filename': file.filename,
            'results': results
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/attack/detail/<int:attack_id>', methods=['GET'])
def get_attack_detail(attack_id):
    """Get detailed information about a specific attack"""
    try:
        conn = db.connect()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM attacks WHERE id = ?", (attack_id,))
        columns = [desc[0] for desc in cursor.description]
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'Attack not found'}), 404
        
        result = dict(zip(columns, row))
        
        # Parse JSON fields
        if result.get('all_detections'):
            result['all_detections'] = json.loads(result['all_detections'])
        
        conn.close()
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/threat-intelligence', methods=['GET'])
def get_threat_intelligence():
    """
    Get threat intelligence summary
    Provides actionable insights and recommendations
    """
    try:
        all_attacks = db.query_attacks()
        malicious = [a for a in all_attacks if a['attack_type'] != 'Benign']
        
        if not malicious:
            return jsonify({
                'message': 'No threats detected',
                'risk_level': 'LOW'
            }), 200
        
        # Calculate risk metrics
        successful_rate = len([a for a in malicious if a['is_successful']]) / len(malicious)
        
        # Most targeted endpoints
        url_targets = {}
        for attack in malicious:
            # Extract base path
            url = attack['url']
            if '?' in url:
                base_url = url.split('?')[0]
            else:
                base_url = url
            url_targets[base_url] = url_targets.get(base_url, 0) + 1
        
        top_targets = sorted(url_targets.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Most common attack vectors
        attack_vector_count = {}
        for attack in malicious:
            attack_type = attack['attack_type']
            attack_vector_count[attack_type] = attack_vector_count.get(attack_type, 0) + 1
        
        # Risk level calculation
        if successful_rate > 0.3:
            risk_level = 'CRITICAL'
        elif successful_rate > 0.15:
            risk_level = 'HIGH'
        elif successful_rate > 0.05:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        # Generate recommendations
        recommendations = []
        
        if 'SQL Injection' in attack_vector_count:
            recommendations.append({
                'threat': 'SQL Injection',
                'priority': 'HIGH',
                'action': 'Implement parameterized queries and input validation',
                'mitigation': 'Use ORM frameworks, enable WAF rules for SQLi'
            })
        
        if 'XSS' in attack_vector_count:
            recommendations.append({
                'threat': 'Cross-Site Scripting',
                'priority': 'HIGH',
                'action': 'Implement output encoding and Content Security Policy',
                'mitigation': 'Sanitize user inputs, use HTTPOnly cookies'
            })
        
        if successful_rate > 0.1:
            recommendations.append({
                'threat': 'High Success Rate',
                'priority': 'CRITICAL',
                'action': 'Review and strengthen security controls immediately',
                'mitigation': 'Conduct security audit, update WAF rules, patch vulnerabilities'
            })
        
        return jsonify({
            'risk_level': risk_level,
            'total_threats': len(malicious),
            'successful_attacks': len([a for a in malicious if a['is_successful']]),
            'success_rate': round(successful_rate * 100, 2),
            'top_attack_vectors': [
                {'type': k, 'count': v} 
                for k, v in sorted(attack_vector_count.items(), 
                                  key=lambda x: x[1], reverse=True)
            ],
            'most_targeted_endpoints': [
                {'url': url, 'attacks': count} 
                for url, count in top_targets
            ],
            'recommendations': recommendations,
            'generated_at': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/realtime/stream', methods=['GET'])
def realtime_stream():
    """
    Server-Sent Events endpoint for real-time attack monitoring
    """
    def generate():
        """Generate real-time updates"""
        import time
        
        while True:
            # Query recent attacks (last 10 seconds)
            recent_time = datetime.now().replace(microsecond=0).isoformat()
            recent_attacks = db.query_attacks({
                'date_from': recent_time
            })
            
            if recent_attacks:
                data = json.dumps({
                    'timestamp': datetime.now().isoformat(),
                    'new_attacks': len(recent_attacks),
                    'attacks': recent_attacks[:5]  # Send last 5
                })
                yield f"data: {data}\n\n"
            
            time.sleep(5)  # Update every 5 seconds
    
    return app.response_class(
        generate(),
        mimetype='text/event-stream'
    )


@app.route('/api/geoip/<ip>', methods=['GET'])
def geoip_lookup(ip):
    """
    Get geographical information for an IP address
    In production, integrate with MaxMind GeoIP2 or ip-api.com
    """
    try:
        # Simulation for artifact
        # In production: use geoip2 or requests to ip-api.com
        
        # Simulated response
        geo_data = {
            'ip': ip,
            'country': 'United States',
            'country_code': 'US',
            'region': 'California',
            'city': 'San Francisco',
            'latitude': 37.7749,
            'longitude': -122.4194,
            'isp': 'Example ISP',
            'org': 'Example Organization'
        }
        
        return jsonify(geo_data), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


# ==================== MAIN ====================

if __name__ == '__main__':
    print("=" * 60)
    print("URL Attack Detection System - Flask API Server")
    print("=" * 60)
    print("\nAvailable Endpoints:")
    print("  GET  /api/health              - Health check")
    print("  POST /api/detect              - Detect single URL")
    print("  POST /api/detect/batch        - Detect multiple URLs")
    print("  GET  /api/attacks             - Query attack records")
    print("  GET  /api/statistics          - Get statistics")
    print("  GET  /api/export/json         - Export as JSON")
    print("  GET  /api/export/csv          - Export as CSV")
    print("  POST /api/pcap/upload         - Upload PCAP file")
    print("  GET  /api/attack/detail/<id>  - Get attack details")
    print("  GET  /api/threat-intelligence - Threat intelligence")
    print("  GET  /api/realtime/stream     - Real-time SSE stream")
    print("  GET  /api/geoip/<ip>          - GeoIP lookup")
    print("\n" + "=" * 60)
    
    # Run server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )
