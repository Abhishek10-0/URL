import React, { useState, useEffect } from 'react';
import {
  Shield,
  Zap,
  Brain,
  Activity,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  TrendingUp,
  Search,
  Copy,
  Download,
  RefreshCw,
  ChevronRight,
  Loader
} from 'lucide-react';

// Clean / Minimal UI version of the CyberShield AI app
// Tailwind must be configured in the host project. This file expects Tailwind + lucide-react to be available.

const App = () => {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('analyze');
  const [copied, setCopied] = useState(false);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/stats');
      if (!response.ok) throw new Error('Network response not ok');
      const data = await response.json();
      setStats(data);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
      // keep silent for UI; stats are optional
    }
  };

  const analyzeInput = async () => {
    if (!input.trim()) {
      alert('⚠️ Please enter some input to analyze!');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input })
      });

      const data = await response.json();
      if (data.success) {
        setResult(data);
        setActiveTab('results');
      } else {
        alert('❌ Error: ' + (data.error || 'Unknown')); 
      }
    } catch (error) {
      alert('❌ Connection failed! Make sure backend is running.');
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    if (!navigator.clipboard) {
      // fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    } else {
      navigator.clipboard.writeText(text);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadReport = () => {
    if (!result) return;
    const report = `THREAT DETECTION REPORT\n========================\nGenerated: ${result.timestamp}\nAnalysis Time: ${result.total_time_ms}ms\n\nINPUT:\n${result.input}\n\nMODEL 1 - PATTERN DETECTOR:\n- Verdict: ${result.model1.verdict}\n- Risk Score: ${result.model1.risk_score}/100\n- Confidence: ${result.model1.confidence}\n- Threats: ${result.model1.threats_detected.join(', ') || 'None'}\n- Detection Time: ${result.model1.detection_time_ms}ms\n\nMODEL 2 - ML CLASSIFIER:\n- Attack Type: ${result.model2.attack_type}\n- Confidence: ${(result.model2.confidence * 100).toFixed(1)}%\n- Severity: ${result.model2.severity.toUpperCase()}\n- Server Risk: ${result.model2.server_risk}/100\n- User Risk: ${result.model2.user_risk}/100`.trim();

    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_report_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const testPayloads = [
    { name: 'SQL Injection', payload: "' OR 1=1--", type: 'sql' },
    { name: 'XSS Attack', payload: "<script>alert('XSS')</script>", type: 'xss' },
    { name: 'Path Traversal', payload: '../../../etc/passwd', type: 'path' },
    { name: 'Command Injection', payload: '; cat /etc/passwd', type: 'cmd' },
    { name: 'UNION SELECT', payload: "1' UNION SELECT * FROM users--", type: 'sql' },
    { name: 'JavaScript Protocol', payload: 'javascript:alert(document.cookie)', type: 'xss' }
  ];

  const getVerdictConfig = (verdict) => {
    const configs = {
      MALICIOUS: { colorClass: 'text-red-600', badgeBg: 'bg-red-50', icon: XCircle },
      SUSPICIOUS: { colorClass: 'text-orange-600', badgeBg: 'bg-orange-50', icon: AlertTriangle },
      WARNING: { colorClass: 'text-yellow-600', badgeBg: 'bg-yellow-50', icon: AlertTriangle },
      LOW_RISK: { colorClass: 'text-sky-600', badgeBg: 'bg-sky-50', icon: Info },
      CLEAN: { colorClass: 'text-green-600', badgeBg: 'bg-green-50', icon: CheckCircle },
      BENIGN: { colorClass: 'text-green-600', badgeBg: 'bg-green-50', icon: CheckCircle }
    };
    return configs[verdict] || configs.CLEAN;
  };

  const getSeverityConfig = (severity) => {
    const configs = {
      critical: { color: 'red', text: 'CRITICAL', emoji: '🔴' },
      high: { color: 'orange', text: 'HIGH', emoji: '🟠' },
      medium: { color: 'yellow', text: 'MEDIUM', emoji: '🟡' },
      low: { color: 'blue', text: 'LOW', emoji: '🔵' },
      none: { color: 'green', text: 'NONE', emoji: '🟢' }
    };
    return configs[severity] || configs.none;
  };

  return (
    <div className="min-h-screen flex bg-gray-50 text-gray-800 font-sans">
      {/* Sidebar */}
      <aside className="w-72 bg-gray-900 text-gray-100 flex flex-col p-6 gap-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gray-800 rounded-md">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">CyberShield AI</h1>
            <p className="text-xs text-gray-400 mt-0.5">Threat Intelligence</p>
          </div>
        </div>

        <nav className="flex-1">
          <button
            onClick={() => setActiveTab('analyze')}
            className={`w-full text-left flex items-center gap-3 px-3 py-2 rounded-md mb-1 ${activeTab === 'analyze' ? 'bg-gray-800' : 'hover:bg-gray-800/60'}`}>
            <Search className="w-4 h-4" />
            <span className="font-medium">Threat Analysis</span>
          </button>

          <button
            onClick={() => setActiveTab('results')}
            className={`w-full text-left flex items-center gap-3 px-3 py-2 rounded-md mb-1 ${activeTab === 'results' ? 'bg-gray-800' : 'hover:bg-gray-800/60'}`}>
            <Activity className="w-4 h-4" />
            <span className="font-medium">Results</span>
          </button>

          <button
            onClick={() => setActiveTab('about')}
            className={`w-full text-left flex items-center gap-3 px-3 py-2 rounded-md ${activeTab === 'about' ? 'bg-gray-800' : 'hover:bg-gray-800/60'}`}>
            <Info className="w-4 h-4" />
            <span className="font-medium">System Info</span>
          </button>
        </nav>

        <div className="text-sm text-gray-400">
          <div>System Status</div>
          <div className="flex items-center gap-2 mt-2">
            <span className="w-2 h-2 bg-green-500 rounded-full" />
            <span className="text-xs">Online</span>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 p-8">
        {/* Header */}
        <header className="flex items-center justify-between mb-6">
          <div>
            <h2 className="text-2xl font-semibold">Threat Dashboard</h2>
            <p className="text-sm text-gray-500">Minimal • Clean • Professional</p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => { setInput(''); setResult(null); setActiveTab('analyze'); }}
              className="px-3 py-2 rounded-md bg-gray-800 text-white text-sm hover:opacity-90">
              New Analysis
            </button>
          </div>
        </header>

        {/* Content area */}
        {activeTab === 'analyze' && (
          <div className="space-y-6">
            <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-gray-100 rounded-md">
                  <Zap className="w-5 h-5 text-gray-700" />
                </div>
                <h3 className="text-lg font-semibold">Threat Input</h3>
              </div>

              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={'Enter suspicious URL, payload or code to analyze...'}
                className="w-full resize-none px-4 py-3 bg-white border border-gray-200 rounded-md text-sm text-gray-800 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-sky-200"
              />

              <div className="flex gap-3 mt-4">
                <button
                  onClick={analyzeInput}
                  disabled={loading}
                  className="flex items-center gap-2 px-4 py-2 rounded-md bg-sky-600 text-white font-medium hover:opacity-95 disabled:opacity-60">
                  {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                  <span>{loading ? 'Analyzing...' : 'Analyze Threat'}</span>
                </button>

                <button
                  onClick={() => setInput('')}
                  className="px-4 py-2 rounded-md border border-gray-200 bg-white text-gray-700 hover:bg-gray-50">
                  Clear
                </button>

                <div className="ml-auto grid grid-cols-2 gap-2 w-64">
                  <div className="text-xs text-gray-500">Quick Payloads</div>
                  <div />
                </div>
              </div>
            </section>

            <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h4 className="text-sm font-semibold mb-3">Quick Test Payloads</h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {testPayloads.map((item, idx) => (
                  <button
                    key={idx}
                    onClick={() => setInput(item.payload)}
                    className="text-left px-3 py-3 border border-gray-100 rounded-md hover:shadow-sm hover:bg-gray-50">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-gray-700">{item.name}</span>
                      <ChevronRight className="w-4 h-4 text-gray-400" />
                    </div>
                    <code className="block text-xs text-gray-500 bg-gray-50 px-2 py-1 rounded mt-1 truncate">{item.payload}</code>
                  </button>
                ))}
              </div>
            </section>

            {stats && (
              <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-5">
                  <div className="flex items-center gap-3 mb-3">
                    <Zap className="w-5 h-5 text-gray-700" />
                    <h4 className="font-semibold">Model 1: Pattern Detector</h4>
                  </div>
                  <div className="text-sm text-gray-600">
                    <div>Version: <strong className="text-gray-800">{stats.model1.version}</strong></div>
                    <div>Patterns: <strong className="text-gray-800">{stats.model1.patterns}</strong></div>
                    <div>Analyses: <strong className="text-gray-800">{stats.model1.analyses}</strong></div>
                  </div>
                </div>

                <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-5">
                  <div className="flex items-center gap-3 mb-3">
                    <Brain className="w-5 h-5 text-gray-700" />
                    <h4 className="font-semibold">Model 2: ML Classifier</h4>
                  </div>
                  <div className="text-sm text-gray-600">
                    <div>Status: <strong className={`text-${stats.model2.loaded ? 'green' : 'red'}-600`}>{stats.model2.loaded ? 'Active' : 'Inactive'}</strong></div>
                    <div>Version: <strong className="text-gray-800">{stats.model2.version}</strong></div>
                    <div>Accuracy: <strong className="text-gray-800">{stats.model2.accuracy}</strong></div>
                  </div>
                </div>
              </section>
            )}
          </div>
        )}

        {/* Results tab */}
        {activeTab === 'results' && (
          <div className="space-y-6">
            {!result ? (
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8 text-center">
                <Activity className="w-14 h-14 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-semibold">No Results Yet</h3>
                <p className="text-sm text-gray-500 mt-2">Analyze an input to get detailed results here.</p>
                <div className="mt-4">
                  <button onClick={() => setActiveTab('analyze')} className="px-4 py-2 rounded-md bg-sky-600 text-white">Go to Analysis</button>
                </div>
              </div>
            ) : (
              <>
                <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                  <div className="flex items-start justify-between gap-4 mb-4">
                    <div>
                      <h4 className="text-lg font-semibold">Analyzed Input</h4>
                      <p className="text-xs text-gray-500 mt-1">Analyzed: {result.timestamp} • Time: {result.total_time_ms}ms</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => copyToClipboard(result.input)} className="px-3 py-2 rounded-md border border-gray-200 bg-white text-gray-700 text-sm flex items-center gap-2"> <Copy className="w-4 h-4" /> {copied ? 'Copied' : 'Copy'}</button>
                      <button onClick={downloadReport} className="px-3 py-2 rounded-md border border-gray-200 bg-white text-gray-700 text-sm flex items-center gap-2"> <Download className="w-4 h-4" /> Report</button>
                    </div>
                  </div>

                  <div className="bg-gray-50 border border-gray-100 rounded p-3 font-mono text-sm text-gray-700 overflow-x-auto">{result.input}</div>
                </section>

                {/* Model 1 */}
                <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-gray-100 rounded-md"><Zap className="w-5 h-5 text-gray-700" /></div>
                      <div>
                        <h4 className="text-lg font-semibold">Model 1: Pattern Detector</h4>
                        <p className="text-xs text-gray-500">Regex-based threat analysis</p>
                      </div>
                    </div>
                    <div className="text-sm text-gray-500">{result.model1.detection_time_ms}ms</div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                    <div className="p-4 border border-gray-100 rounded-md">
                      <div className="text-sm text-gray-500 mb-1">Verdict</div>
                      <div className={`text-2xl font-bold ${getVerdictConfig(result.model1.verdict).colorClass}`}>{result.model1.verdict}</div>
                      <div className={`mt-2 inline-flex items-center gap-2 px-2 py-1 rounded ${getVerdictConfig(result.model1.verdict).badgeBg}`}>
                        {React.createElement(getVerdictConfig(result.model1.verdict).icon, { className: 'w-4 h-4' })}
                        <span className="text-sm font-semibold text-gray-700">{result.model1.confidence}</span>
                      </div>
                    </div>

                    <div className="p-4 border border-gray-100 rounded-md">
                      <div className="text-sm text-gray-500 mb-1">Risk Score</div>
                      <div className="text-2xl font-bold text-gray-800 mb-2">{result.model1.risk_score}/100</div>
                      <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                        <div className="h-full bg-sky-500 transition-all" style={{ width: `${result.model1.risk_score}%` }} />
                      </div>
                    </div>

                    <div className="p-4 border border-gray-100 rounded-md">
                      <div className="text-sm text-gray-500 mb-1">Threats Detected</div>
                      <div className="text-2xl font-bold text-gray-800 mb-1">{result.model1.threats_detected.length}</div>
                      <div className="text-sm text-gray-600">{result.model1.threats_detected.length > 0 ? 'Attack patterns found' : 'No threats detected'}</div>
                    </div>
                  </div>

                  {result.model1.threats_detected.length > 0 && (
                    <div className="p-4 border border-red-50 bg-red-50 rounded-md">
                      <div className="flex items-center gap-2 text-sm font-semibold text-red-700 mb-3"><AlertTriangle className="w-4 h-4" /> Detected Threat Patterns</div>
                      <div className="flex flex-wrap gap-2">
                        {result.model1.threats_detected.map((t, i) => (
                          <div key={i} className="px-3 py-1 bg-white border border-red-100 rounded-md text-sm text-red-700">{t}</div>
                        ))}
                      </div>
                    </div>
                  )}
                </section>

                {/* Model 2 */}
                <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-gray-100 rounded-md"><Brain className="w-5 h-5 text-gray-700" /></div>
                      <div>
                        <h4 className="text-lg font-semibold">Model 2: ML Classifier</h4>
                        <p className="text-xs text-gray-500">XGBoost machine learning</p>
                      </div>
                    </div>

                    <div className="px-3 py-1 rounded-md text-sm border border-gray-100 bg-gray-50">
                      {getSeverityConfig(result.model2.severity).emoji} {getSeverityConfig(result.model2.severity).text}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 border border-gray-100 rounded-md">
                      <div className="text-sm text-gray-500 mb-2">Attack Classification</div>
                      <div className="text-xl font-bold text-gray-800 mb-2">{result.model2.attack_type}</div>
                      <div className="flex items-center gap-2 mb-2">
                        <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
                          <div className="h-full bg-pink-500 transition-all" style={{ width: `${result.model2.confidence * 100}%` }} />
                        </div>
                        <div className="text-sm font-semibold text-gray-700">{(result.model2.confidence * 100).toFixed(1)}%</div>
                      </div>
                      <div className="text-xs text-gray-500">Model Confidence Score</div>
                    </div>

                    <div className="p-4 border border-gray-100 rounded-md">
                      <div className="text-sm text-gray-500 mb-3">Risk Assessment</div>
                      <div className="space-y-3">
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-sm text-gray-700">Server Risk</span>
                            <span className="font-bold text-gray-800">{result.model2.server_risk}/100</span>
                          </div>
                          <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                            <div className="h-full bg-orange-500 transition-all" style={{ width: `${result.model2.server_risk}%` }} />
                          </div>
                        </div>

                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-sm text-gray-700">User Risk</span>
                            <span className="font-bold text-gray-800">{result.model2.user_risk}/100</span>
                          </div>
                          <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                            <div className="h-full bg-yellow-500 transition-all" style={{ width: `${result.model2.user_risk}%` }} />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </section>

                {/* Final Verdict */}
                <section className={`p-6 rounded-xl border ${['critical','high'].includes(result.model2.severity) ? 'border-red-100 bg-red-50' : 'border-green-100 bg-green-50'}`}>
                  <div className="flex items-center gap-4">
                    {['critical','high'].includes(result.model2.severity) ? (
                      <XCircle className="w-12 h-12 text-red-600" />
                    ) : (
                      <CheckCircle className="w-12 h-12 text-green-600" />
                    )}

                    <div className="flex-1">
                      <div className="text-xl font-bold text-gray-800">{['critical','high'].includes(result.model2.severity) ? '⚠️ THREAT DETECTED' : '✅ INPUT APPEARS SAFE'}</div>
                      <p className="text-sm text-gray-600 mt-1">{['critical','high'].includes(result.model2.severity) ? 'Malicious patterns detected. This input poses a security risk.' : 'No significant threats found. Input appears to be benign.'}</p>
                    </div>

                    <div className="flex gap-2">
                      <button onClick={() => setActiveTab('analyze')} className="px-3 py-2 rounded-md bg-white border border-gray-200"> <RefreshCw className="w-4 h-4" /> New Analysis</button>
                    </div>
                  </div>
                </section>
              </>
            )}
          </div>
        )}

        {/* About tab */}
        {activeTab === 'about' && (
          <div className="space-y-6">
            <section className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold mb-4">System Architecture</h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 border rounded-md border-gray-100">
                  <div className="flex items-center gap-3 mb-3"><Zap className="w-5 h-5 text-gray-700" /><h4 className="font-semibold">Model 1: Pattern Detector</h4></div>
                  <ul className="text-sm text-gray-600 list-disc list-inside space-y-2">
                    <li>Fast regex-based detection (~50ms)</li>
                    <li>250+ attack patterns</li>
                    <li>Real-time threat scoring</li>
                    <li>CSV-based pattern management</li>
                  </ul>
                </div>

                <div className="p-4 border rounded-md border-gray-100">
                  <div className="flex items-center gap-3 mb-3"><Brain className="w-5 h-5 text-gray-700" /><h4 className="font-semibold">Model 2: ML Classifier</h4></div>
                  <ul className="text-sm text-gray-600 list-disc list-inside space-y-2">
                    <li>XGBoost machine learning</li>
                    <li>120 extracted features</li>
                    <li>95%+ accuracy</li>
                    <li>Advanced risk assessment</li>
                  </ul>
                </div>
              </div>

              <div className="mt-4 p-3 border rounded-md border-gray-100 bg-gray-50">
                <h5 className="font-semibold text-sm mb-2">Detection Capabilities</h5>
                <div className="flex flex-wrap gap-2 text-sm">
                  {[
                    'SQL Injection', 'XSS', 'Path Traversal', 'Command Injection',
                    'LDAP Injection', 'NoSQL Injection', 'XXE', 'CRLF Injection',
                    'LFI/RFI', 'Open Redirect', 'Phishing', 'Generic Attacks'
                  ].map((attack, idx) => (
                    <div key={idx} className="px-2 py-1 bg-white border border-gray-100 rounded text-gray-700 text-xs">{attack}</div>
                  ))}
                </div>
              </div>
            </section>
          </div>
        )}
      </main>
    </div>
  );
};

export default App;
