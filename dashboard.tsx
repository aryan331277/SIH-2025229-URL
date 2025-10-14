import React, { useState, useEffect } from 'react';
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { AlertTriangle, Upload, Download, Search, Filter, Globe, Shield, Activity, Database } from 'lucide-react';

// Simulated ML Detection Engine
class AttackDetector {
  constructor() {
    this.attackPatterns = {
      'SQL Injection': [
        /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
        /(union|select|insert|update|delete|drop|create|alter|exec|script|javascript|onerror)/i,
        /(\bunion\b.*\bselect\b)|(\bor\b.*=.*)/i
      ],
      'XSS': [
        /<script[^>]*>.*?<\/script>/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /<iframe/i,
        /alert\(|prompt\(|confirm\(/i
      ],
      'Directory Traversal': [
        /\.\.\/|\.\.%2[fF]/i,
        /(\.\.\\|\.\.%5[cC])/i,
        /etc\/passwd|windows\/system32/i
      ],
      'Command Injection': [
        /[;&|`$()]/,
        /(bash|sh|cmd|powershell|wget|curl)\s/i,
        /\|\||&&/
      ],
      'SSRF': [
        /localhost|127\.0\.0\.1|0\.0\.0\.0/i,
        /file:\/\/|dict:\/\/|gopher:\/\//i,
        /@(10|172|192)\./i
      ],
      'LFI/RFI': [
        /\.(php|asp|jsp|cgi)[?&]/i,
        /(include|require).*\(/i,
        /file=.*\.(php|txt|log)/i
      ],
      'Credential Stuffing': [
        /(login|signin|auth).*password/i,
        /username.*password/i,
        /(admin|root|user).*password/i
      ],
      'Parameter Pollution': [
        /(&|\?)(\w+)=.*&\1=/i
      ],
      'XXE Injection': [
        /<!ENTITY/i,
        /<!DOCTYPE.*ENTITY/i,
        /SYSTEM.*file:/i
      ],
      'Web Shell': [
        /cmd\.jsp|shell\.php|backdoor\.asp/i,
        /c99\.php|r57\.php/i,
        /eval\(|base64_decode\(/i
      ],
      'Typosquatting': [
        /(g00gle|yah00|faceb00k|micr0soft)/i,
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
      ]
    };
  }

  detectAttack(url) {
    const detections = [];
    let maxConfidence = 0;
    let primaryAttack = 'Benign';

    for (const [attackType, patterns] of Object.entries(this.attackPatterns)) {
      let matches = 0;
      for (const pattern of patterns) {
        if (pattern.test(url)) {
          matches++;
        }
      }
      
      if (matches > 0) {
        const confidence = Math.min(95, 60 + (matches * 15));
        detections.push({ type: attackType, confidence });
        
        if (confidence > maxConfidence) {
          maxConfidence = confidence;
          primaryAttack = attackType;
        }
      }
    }

    const isSuccessful = maxConfidence > 70 && Math.random() > 0.4;

    return {
      primaryAttack,
      confidence: maxConfidence || 0,
      allDetections: detections,
      isSuccessful,
      isMalicious: maxConfidence > 0
    };
  }
}

// Sample data generator
const generateSampleData = (count = 100) => {
  const detector = new AttackDetector();
  const attacks = [
    "http://example.com/page?id=1' OR '1'='1",
    "http://test.com/search?q=<script>alert('XSS')</script>",
    "http://site.com/file?path=../../etc/passwd",
    "http://api.com/exec?cmd=ls;cat /etc/passwd",
    "http://server.com/proxy?url=http://localhost:8080",
    "http://app.com/load?file=../../../config.php",
    "http://login.com/auth?user=admin&pass=admin123",
    "http://form.com/submit?id=1&id=2&name=test",
    "http://xml.com/parse?data=<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
    "http://upload.com/files/cmd.jsp",
    "http://g00gle.com/phishing",
    "http://normal.com/page?id=123",
    "http://safe.com/search?q=hello",
    "http://example.com/user/profile",
  ];

  const ips = ['192.168.1.', '10.0.0.', '172.16.0.', '203.0.113.', '198.51.100.'];
  const data = [];

  for (let i = 0; i < count; i++) {
    const url = attacks[Math.floor(Math.random() * attacks.length)];
    const detection = detector.detectAttack(url);
    const ip = ips[Math.floor(Math.random() * ips.length)] + Math.floor(Math.random() * 255);
    const timestamp = new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000);

    data.push({
      id: i + 1,
      url,
      ip,
      timestamp: timestamp.toISOString(),
      attackType: detection.primaryAttack,
      confidence: detection.confidence,
      isSuccessful: detection.isSuccessful,
      isMalicious: detection.isMalicious,
      allDetections: detection.allDetections
    });
  }

  return data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
};

const Dashboard = () => {
  const [data, setData] = useState([]);
  const [filteredData, setFilteredData] = useState([]);
  const [filters, setFilters] = useState({
    attackType: 'all',
    ipRange: '',
    status: 'all',
    dateFrom: '',
    dateTo: ''
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEntry, setSelectedEntry] = useState(null);
  const [uploadedFile, setUploadedFile] = useState(null);

  useEffect(() => {
    const initialData = generateSampleData(150);
    setData(initialData);
    setFilteredData(initialData);
  }, []);

  useEffect(() => {
    let filtered = [...data];

    if (filters.attackType !== 'all') {
      filtered = filtered.filter(d => d.attackType === filters.attackType);
    }

    if (filters.ipRange) {
      filtered = filtered.filter(d => d.ip.startsWith(filters.ipRange));
    }

    if (filters.status === 'successful') {
      filtered = filtered.filter(d => d.isSuccessful);
    } else if (filters.status === 'attempt') {
      filtered = filtered.filter(d => d.isMalicious && !d.isSuccessful);
    }

    if (searchTerm) {
      filtered = filtered.filter(d => 
        d.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
        d.ip.includes(searchTerm)
      );
    }

    if (filters.dateFrom) {
      filtered = filtered.filter(d => new Date(d.timestamp) >= new Date(filters.dateFrom));
    }

    if (filters.dateTo) {
      filtered = filtered.filter(d => new Date(d.timestamp) <= new Date(filters.dateTo));
    }

    setFilteredData(filtered);
  }, [filters, searchTerm, data]);

  const exportData = (format) => {
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(filteredData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `attack_report_${Date.now()}.json`;
      a.click();
    } else if (format === 'csv') {
      const headers = ['ID', 'Timestamp', 'IP', 'Attack Type', 'Confidence', 'Status', 'URL'];
      const rows = filteredData.map(d => [
        d.id,
        d.timestamp,
        d.ip,
        d.attackType,
        d.confidence,
        d.isSuccessful ? 'Successful' : (d.isMalicious ? 'Attempt' : 'Benign'),
        d.url
      ]);
      
      const csv = [headers, ...rows].map(row => row.map(cell => `"${cell}"`).join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `attack_report_${Date.now()}.csv`;
      a.click();
    }
  };

  const handlePcapUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      setUploadedFile(file.name);
      // Simulate PCAP processing
      setTimeout(() => {
        const newData = generateSampleData(30);
        setData([...newData, ...data]);
        alert(`Processed ${file.name}: Found ${newData.filter(d => d.isMalicious).length} potential attacks`);
      }, 1500);
    }
  };

  // Analytics calculations
  const attackTypeDistribution = Object.entries(
    filteredData.reduce((acc, d) => {
      if (d.isMalicious) {
        acc[d.attackType] = (acc[d.attackType] || 0) + 1;
      }
      return acc;
    }, {})
  ).map(([name, value]) => ({ name, value }));

  const timelineData = filteredData
    .filter(d => d.isMalicious)
    .reduce((acc, d) => {
      const date = new Date(d.timestamp).toLocaleDateString();
      const existing = acc.find(a => a.date === date);
      if (existing) {
        existing.attacks++;
      } else {
        acc.push({ date, attacks: 1 });
      }
      return acc;
    }, [])
    .sort((a, b) => new Date(a.date) - new Date(b.date));

  const successRate = filteredData.filter(d => d.isMalicious).length > 0
    ? [
        { name: 'Successful', value: filteredData.filter(d => d.isSuccessful).length },
        { name: 'Blocked', value: filteredData.filter(d => d.isMalicious && !d.isSuccessful).length }
      ]
    : [];

  const COLORS = ['#ef4444', '#f97316', '#f59e0b', '#eab308', '#84cc16', '#22c55e', '#10b981', '#14b8a6', '#06b6d4', '#0ea5e9', '#3b82f6'];

  const uniqueAttackTypes = ['all', ...new Set(data.map(d => d.attackType))];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <Shield className="w-10 h-10 text-red-500" />
            <div>
              <h1 className="text-3xl font-bold">URL Attack Detection System</h1>
              <p className="text-gray-400">Real-time HTTP threat intelligence & analysis</p>
            </div>
          </div>
          <div className="flex space-x-3">
            <button
              onClick={() => exportData('json')}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition"
            >
              <Download className="w-4 h-4" />
              <span>Export JSON</span>
            </button>
            <button
              onClick={() => exportData('csv')}
              className="flex items-center space-x-2 px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg transition"
            >
              <Download className="w-4 h-4" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Requests</p>
                <p className="text-2xl font-bold">{filteredData.length}</p>
              </div>
              <Database className="w-8 h-8 text-blue-500" />
            </div>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg border border-red-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Malicious Attempts</p>
                <p className="text-2xl font-bold text-red-500">{filteredData.filter(d => d.isMalicious).length}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg border border-orange-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Successful Attacks</p>
                <p className="text-2xl font-bold text-orange-500">{filteredData.filter(d => d.isSuccessful).length}</p>
              </div>
              <Activity className="w-8 h-8 text-orange-500" />
            </div>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg border border-green-700">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Blocked Attacks</p>
                <p className="text-2xl font-bold text-green-500">{filteredData.filter(d => d.isMalicious && !d.isSuccessful).length}</p>
              </div>
              <Shield className="w-8 h-8 text-green-500" />
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 mb-6">
          <div className="flex items-center space-x-2 mb-4">
            <Filter className="w-5 h-5 text-gray-400" />
            <h2 className="text-lg font-semibold">Filters & Search</h2>
          </div>
          <div className="grid grid-cols-5 gap-4">
            <div>
              <label className="text-sm text-gray-400 block mb-1">Attack Type</label>
              <select
                value={filters.attackType}
                onChange={(e) => setFilters({...filters, attackType: e.target.value})}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
              >
                {uniqueAttackTypes.map(type => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-sm text-gray-400 block mb-1">Status</label>
              <select
                value={filters.status}
                onChange={(e) => setFilters({...filters, status: e.target.value})}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
              >
                <option value="all">All</option>
                <option value="successful">Successful</option>
                <option value="attempt">Attempts</option>
              </select>
            </div>
            <div>
              <label className="text-sm text-gray-400 block mb-1">IP Range</label>
              <input
                type="text"
                placeholder="e.g., 192.168"
                value={filters.ipRange}
                onChange={(e) => setFilters({...filters, ipRange: e.target.value})}
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="text-sm text-gray-400 block mb-1">Search URL/IP</label>
              <div className="relative">
                <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search..."
                  className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 pl-10 text-sm"
                />
              </div>
            </div>
            <div>
              <label className="text-sm text-gray-400 block mb-1">Upload PCAP</label>
              <label className="flex items-center justify-center w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm cursor-pointer hover:bg-gray-600">
                <Upload className="w-4 h-4 mr-2" />
                <span>{uploadedFile || 'Choose file'}</span>
                <input
                  type="file"
                  accept=".pcap,.pcapng"
                  onChange={handlePcapUpload}
                  className="hidden"
                />
              </label>
            </div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-3 gap-6 mb-6">
        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
          <h3 className="text-lg font-semibold mb-4">Attack Type Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={attackTypeDistribution}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={(entry) => entry.name}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {attackTypeDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
          <h3 className="text-lg font-semibold mb-4">Attack Timeline</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="date" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }} />
              <Line type="monotone" dataKey="attacks" stroke="#ef4444" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
          <h3 className="text-lg font-semibold mb-4">Success vs Blocked</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={successRate}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }} />
              <Bar dataKey="value" fill="#f59e0b" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Data Table */}
      <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-700">
          <h2 className="text-lg font-semibold">Detection Log</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-700">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-semibold">ID</th>
                <th className="px-4 py-3 text-left text-sm font-semibold">Timestamp</th>
                <th className="px-4 py-3 text-left text-sm font-semibold">IP Address</th>
                <th className="px-4 py-3 text-left text-sm font-semibold">Attack Type</th>
                <th className="px-4 py-3 text-left text-sm font-semibold">Confidence</th>
                <th className="px-4 py-3 text-left text-sm font-semibold">Status</th>
                <th className="px-4 py-3 text-left text-sm font-semibold">URL</th>
              </tr>
            </thead>
            <tbody>
              {filteredData.slice(0, 50).map((entry, idx) => (
                <tr
                  key={entry.id}
                  onClick={() => setSelectedEntry(entry)}
                  className={`cursor-pointer hover:bg-gray-700 ${idx % 2 === 0 ? 'bg-gray-800' : 'bg-gray-750'}`}
                >
                  <td className="px-4 py-3 text-sm">{entry.id}</td>
                  <td className="px-4 py-3 text-sm">{new Date(entry.timestamp).toLocaleString()}</td>
                  <td className="px-4 py-3 text-sm font-mono">{entry.ip}</td>
                  <td className="px-4 py-3 text-sm">
                    <span className={`px-2 py-1 rounded text-xs ${entry.isMalicious ? 'bg-red-900 text-red-200' : 'bg-green-900 text-green-200'}`}>
                      {entry.attackType}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <div className="flex items-center space-x-2">
                      <div className="w-20 bg-gray-600 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${entry.confidence > 70 ? 'bg-red-500' : entry.confidence > 40 ? 'bg-orange-500' : 'bg-yellow-500'}`}
                          style={{ width: `${entry.confidence}%` }}
                        ></div>
                      </div>
                      <span className="text-xs">{entry.confidence}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {entry.isSuccessful ? (
                      <span className="px-2 py-1 bg-orange-900 text-orange-200 rounded text-xs">Successful</span>
                    ) : entry.isMalicious ? (
                      <span className="px-2 py-1 bg-yellow-900 text-yellow-200 rounded text-xs">Blocked</span>
                    ) : (
                      <span className="px-2 py-1 bg-green-900 text-green-200 rounded text-xs">Benign</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm font-mono text-gray-300 truncate max-w-xs">{entry.url}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Modal */}
      {selectedEntry && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50" onClick={() => setSelectedEntry(null)}>
          <div className="bg-gray-800 rounded-lg p-6 max-w-3xl w-full m-4 border border-gray-700" onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between items-start mb-4">
              <h2 className="text-xl font-bold">Detection Details</h2>
              <button onClick={() => setSelectedEntry(null)} className="text-gray-400 hover:text-white">✕</button>
            </div>
            <div className="space-y-3">
              <div><span className="text-gray-400">ID:</span> <span className="font-mono">{selectedEntry.id}</span></div>
              <div><span className="text-gray-400">Timestamp:</span> {new Date(selectedEntry.timestamp).toLocaleString()}</div>
              <div><span className="text-gray-400">IP Address:</span> <span className="font-mono">{selectedEntry.ip}</span></div>
              <div><span className="text-gray-400">Primary Attack:</span> <span className={`font-semibold ${selectedEntry.isMalicious ? 'text-red-400' : 'text-green-400'}`}>{selectedEntry.attackType}</span></div>
              <div><span className="text-gray-400">Confidence:</span> {selectedEntry.confidence}%</div>
              <div><span className="text-gray-400">Status:</span> {selectedEntry.isSuccessful ? '🔴 Successful Attack' : selectedEntry.isMalicious ? '🟡 Blocked Attempt' : '🟢 Benign'}</div>
              <div className="pt-2 border-t border-gray-700">
                <span className="text-gray-400 block mb-2">URL:</span>
                <div className="bg-gray-900 p-3 rounded font-mono text-sm break-all">{selectedEntry.url}</div>
              </div>
              {selectedEntry.allDetections.length > 0 && (
                <div className="pt-2 border-t border-gray-700">
                  <span className="text-gray-400 block mb-2">All Detections:</span>
                  <div className="space-y-2">
                    {selectedEntry.allDetections.map((det, idx) => (
                      <div key={idx} className="bg-gray-900 p-2 rounded text-sm">
                        <span className="font-semibold text-red-400">{det.type}</span>
                        <span className="text-gray-400 ml-2">({det.confidence}% confidence)</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
