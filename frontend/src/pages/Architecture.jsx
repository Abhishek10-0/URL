import React, { useState } from 'react';
import { Shield, Zap, Database, RefreshCw, AlertTriangle, CheckCircle, Settings, Globe, FileText, Activity, Eye, ArrowRight, ArrowDown } from 'lucide-react';

const ThreatDetectionArchitecture = () => {
  const [selectedComponent, setSelectedComponent] = useState(null);

  return (
    <div className="w-full min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white p-8 overflow-auto">
      {/* Header */}
      <div className="text-center mb-8">
        <div className="flex items-center justify-center gap-3 mb-4">
          <Shield className="w-12 h-12 text-blue-400" />
          <h1 className="text-4xl font-bold">Bidirectional Threat Detection System</h1>
        </div>
        <p className="text-xl text-gray-400">Complete Detection & Learning Architecture</p>
      </div>

      <div className="max-w-[1600px] mx-auto">
        {/* User Input */}
        <div className="flex justify-center mb-6">
          <div className="bg-gray-800 border-2 border-gray-600 rounded-lg p-4 text-center">
            <AlertTriangle className="w-8 h-8 mx-auto mb-2 text-yellow-400" />
            <div className="font-bold">USER INPUT SOURCES</div>
            <div className="text-sm text-gray-400 mt-1">Single URL • Bulk Payloads • JSON • PCAP Files</div>
          </div>
        </div>

        {/* Arrow Down */}
        <div className="flex justify-center mb-6">
          <ArrowDown className="w-6 h-6 text-blue-400" />
        </div>

        {/* PHASE 1: DETECTION ENGINE */}
        <div className="bg-gradient-to-br from-blue-900 to-blue-950 border-2 border-blue-500 rounded-xl p-6 mb-8">
          <div className="text-center mb-6">
            <h2 className="text-2xl font-bold text-blue-300">⚡ PHASE 1: DETECTION ENGINE</h2>
            <p className="text-sm text-blue-200">Real-Time Detection (200ms)</p>
          </div>

          <div className="flex flex-wrap justify-center items-center gap-4">
            {/* Model 1 */}
            <div className="bg-blue-800 bg-opacity-50 rounded-lg p-4 border border-blue-400 w-48">
              <Shield className="w-6 h-6 mx-auto mb-2" />
              <div className="text-center font-semibold">Model 1</div>
              <div className="text-xs text-center">Pattern Detector</div>
              <div className="text-xs text-center text-blue-300">50ms</div>
            </div>

            <ArrowRight className="w-6 h-6 text-blue-400" />

            {/* Verdict Combiner */}
            <div className="bg-blue-800 bg-opacity-50 rounded-lg p-4 border border-blue-400 w-48">
              <Settings className="w-6 h-6 mx-auto mb-2" />
              <div className="text-center font-semibold">Verdict Combiner</div>
              <div className="text-xs text-center text-blue-300">10ms</div>
            </div>

            <ArrowRight className="w-6 h-6 text-blue-400" />

            {/* To User */}
            <div className="bg-blue-800 bg-opacity-50 rounded-lg p-4 border border-blue-400 w-32">
              <CheckCircle className="w-6 h-6 mx-auto mb-2 text-green-400" />
              <div className="text-center font-semibold text-sm">To User</div>
              <div className="text-xs text-center text-blue-300">200ms</div>
            </div>
          </div>

          <div className="flex flex-wrap justify-center items-center gap-4 mt-4">
            {/* Model 2 */}
            <div className="bg-blue-800 bg-opacity-50 rounded-lg p-4 border border-blue-400 w-48">
              <Zap className="w-6 h-6 mx-auto mb-2" />
              <div className="text-center font-semibold">Model 2</div>
              <div className="text-xs text-center">ML Classifier</div>
              <div className="text-xs text-center text-blue-300">150ms</div>
            </div>

            <div className="w-48"></div>

            {/* Data Logger */}
            <div className="bg-blue-800 bg-opacity-50 rounded-lg p-4 border border-blue-400 w-48">
              <FileText className="w-6 h-6 mx-auto mb-2" />
              <div className="text-center font-semibold">Data Logger</div>
              <div className="text-xs text-center text-blue-300">Background</div>
            </div>
          </div>
        </div>

        {/* Branching Arrows */}
        <div className="flex justify-center items-start mb-6 gap-8">
          <div className="flex flex-col items-center">
            <div className="text-xs text-amber-400 mb-2">user-triggered</div>
            <ArrowDown className="w-6 h-6 text-amber-400" />
          </div>
          <div className="flex flex-col items-center">
            <div className="text-xs text-amber-400 mb-2">gold labels</div>
            <ArrowDown className="w-6 h-6 text-amber-400" />
          </div>
          <div className="flex flex-col items-center">
            <div className="text-xs text-amber-400 mb-2">continuous logs</div>
            <ArrowDown className="w-6 h-6 text-amber-400" />
          </div>
          <div className="flex flex-col items-center">
            <div className="text-xs text-amber-400 mb-2">batch evidence</div>
            <ArrowDown className="w-6 h-6 text-amber-400" />
          </div>
        </div>

        {/* PHASE 2: VALIDATION & ENRICHMENT */}
        <div className="bg-gradient-to-br from-amber-900 to-amber-950 border-2 border-amber-500 rounded-xl p-6 mb-8">
          <div className="text-center mb-6">
            <h2 className="text-2xl font-bold text-amber-300">🔍 PHASE 2: VALIDATION & ENRICHMENT</h2>
            <p className="text-sm text-amber-200">Optional - User Triggered / Automated</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Remote Browsing */}
            <div className="bg-amber-800 bg-opacity-50 rounded-lg p-6 border border-amber-400">
              <Globe className="w-8 h-8 mx-auto mb-3 text-yellow-300" />
              <div className="text-center font-bold text-lg mb-2">Remote Browsing</div>
              <div className="text-xs text-center mb-3 text-amber-300">2 min/session</div>
              
              <div className="bg-amber-900 bg-opacity-50 rounded p-3 text-xs space-y-1">
                <div className="font-semibold text-yellow-300">⭐ GOLD LABELS</div>
                <div>• User safely visits URL</div>
                <div>• VNC connection</div>
                <div>• Capture traffic</div>
                <div>• Monitor JS behavior</div>
                <div>• Record outcomes</div>
                <div className="text-yellow-300 mt-2">Volume: LOW (50/week)</div>
                <div className="text-yellow-300">Quality: VERY HIGH</div>
              </div>
            </div>

            {/* Passive Logging */}
            <div className="bg-amber-800 bg-opacity-50 rounded-lg p-6 border border-amber-400">
              <Eye className="w-8 h-8 mx-auto mb-3" />
              <div className="text-center font-bold text-lg mb-2">Passive Logging</div>
              <div className="text-xs text-center mb-3 text-amber-300">Continuous</div>
              
              <div className="bg-amber-900 bg-opacity-50 rounded p-3 text-xs space-y-1">
                <div className="font-semibold">Standard Detection</div>
                <div>• All detections logged</div>
                <div>• Model outputs saved</div>
                <div>• Quick logging</div>
                <div>• No verification</div>
                <div>• Pattern trends</div>
                <div className="text-amber-300 mt-2">Volume: HIGH (3500/week)</div>
                <div className="text-amber-300">Quality: MEDIUM</div>
              </div>
            </div>

            {/* PCAP Analysis */}
            <div className="bg-amber-800 bg-opacity-50 rounded-lg p-6 border border-amber-400">
              <Activity className="w-8 h-8 mx-auto mb-3" />
              <div className="text-center font-bold text-lg mb-2">PCAP Analysis</div>
              <div className="text-xs text-center mb-3 text-amber-300">5 min/50k requests</div>
              
              <div className="bg-amber-900 bg-opacity-50 rounded p-3 text-xs space-y-1">
                <div className="font-semibold">Server Evidence</div>
                <div>• Batch processing</div>
                <div>• Request-Response pairs</div>
                <div>• HTTP status codes</div>
                <div>• Error messages</div>
                <div>• Attack patterns</div>
                <div className="text-amber-300 mt-2">Volume: VERY HIGH</div>
                <div className="text-amber-300">Quality: HIGH</div>
              </div>
            </div>
          </div>
        </div>

        {/* Arrow Down to Data Lake */}
        <div className="flex justify-center mb-6">
          <div className="flex flex-col items-center">
            <div className="text-xs text-purple-400 mb-2">training data</div>
            <ArrowDown className="w-6 h-6 text-purple-400" />
          </div>
        </div>

        {/* DATA LAKE */}
        <div className="bg-gradient-to-br from-purple-900 to-purple-950 border-2 border-purple-500 rounded-xl p-6 mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Database className="w-10 h-10 text-purple-300" />
            <h2 className="text-3xl font-bold text-purple-300">DATA LAKE (JSONL Storage)</h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-purple-800 bg-opacity-50 rounded-lg p-4 border border-purple-400 text-center">
              <div className="text-3xl font-bold">3,500</div>
              <div className="text-sm text-purple-300">analysis_log.jsonl</div>
              <div className="text-xs opacity-75">per week • Model predictions</div>
            </div>
            <div className="bg-purple-800 bg-opacity-50 rounded-lg p-4 border border-purple-400 text-center">
              <div className="text-3xl font-bold text-yellow-300">50 ⭐</div>
              <div className="text-sm text-purple-300">remote_browsing.jsonl</div>
              <div className="text-xs opacity-75">per week • 100% accurate</div>
            </div>
            <div className="bg-purple-800 bg-opacity-50 rounded-lg p-4 border border-purple-400 text-center">
              <div className="text-3xl font-bold">50,000</div>
              <div className="text-sm text-purple-300">pcap_analysis.jsonl</div>
              <div className="text-xs opacity-75">per upload • Server evidence</div>
            </div>
          </div>
        </div>

        {/* Arrow Down to Learning */}
        <div className="flex justify-center mb-6">
          <div className="flex flex-col items-center">
            <div className="text-xs text-green-400 mb-2">weekly retraining</div>
            <ArrowDown className="w-6 h-6 text-green-400" />
          </div>
        </div>

        {/* PHASE 3: LEARNING & IMPROVEMENT */}
        <div className="bg-gradient-to-br from-green-900 to-green-950 border-2 border-green-500 rounded-xl p-6 mb-8">
          <div className="text-center mb-6">
            <h2 className="text-2xl font-bold text-green-300">🔄 PHASE 3: LEARNING & IMPROVEMENT</h2>
            <p className="text-sm text-green-200">Weekly - Sundays (Human Supervised)</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Model 1 Improvement */}
            <div className="bg-green-800 bg-opacity-50 rounded-lg p-6 border border-green-400">
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-6 h-6" />
                <div className="font-bold text-lg">Model 1 Improvement</div>
              </div>
              
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">1</div>
                  <div>Pattern Discovery</div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">2</div>
                  <div>Pattern Validation</div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">3</div>
                  <div>Human Review</div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">4</div>
                  <div>Pattern Addition</div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">5</div>
                  <div>Hot-Reload & Test</div>
                </div>
              </div>
              
              <div className="mt-4 bg-green-900 bg-opacity-50 rounded p-2 text-xs text-green-300">
                <div>Time: ~30 min (mostly manual)</div>
                <div>Patterns: +12 per week</div>
              </div>
            </div>

            {/* Model 2 Retraining */}
            <div className="bg-green-800 bg-opacity-50 rounded-lg p-6 border border-green-400">
              <div className="flex items-center gap-2 mb-4">
                <RefreshCw className="w-6 h-6" />
                <div className="font-bold text-lg">Model 2 Retraining</div>
              </div>
              
              <div className="space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">1</div>
                  <div>Data Aggregation</div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">2</div>
                  <div>Feature Extraction</div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">3</div>
                  <div>XGBoost Training</div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">4</div>
                  <div>Model Validation</div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">5</div>
                  <div>Human Approval</div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center text-xs">6</div>
                  <div>Model Deployed</div>
                </div>
              </div>
              
              <div className="mt-4 bg-green-900 bg-opacity-50 rounded p-2 text-xs text-green-300">
                <div>Time: ~2 hours (automated)</div>
                <div>Accuracy: 92.3% → 94.7%</div>
              </div>
            </div>
          </div>
        </div>

        {/* Feedback Loop Arrow */}
        <div className="flex justify-center mb-6">
          <div className="flex flex-col items-center">
            <div className="text-xs text-blue-400 mb-2">updated models (weekly hot-reload)</div>
            <div className="text-2xl">↻</div>
          </div>
        </div>

        {/* Final Output */}
        <div className="flex justify-center">
          <div className="bg-gradient-to-br from-cyan-900 to-cyan-950 border-2 border-cyan-500 rounded-lg p-6 text-center">
            <CheckCircle className="w-12 h-12 mx-auto mb-3 text-cyan-300" />
            <div className="text-2xl font-bold mb-2">COMPLETE SYSTEM IMPROVED</div>
            <div className="text-sm text-cyan-300">Models get smarter every week • Zero downtime</div>
          </div>
        </div>

        {/* Legend */}
        <div className="mt-8 bg-gray-800 rounded-xl p-6">
          <h3 className="font-bold mb-4 text-center">System Flow Paths</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 bg-blue-500 rounded"></div>
              <div><span className="font-semibold">Regular Path:</span> User Input → Detection → Response (200ms)</div>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 bg-amber-500 rounded"></div>
              <div><span className="font-semibold">Enrichment Path:</span> Detection → Validation → Gold Labels (minutes)</div>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 bg-green-500 rounded"></div>
              <div><span className="font-semibold">Learning Path:</span> Data Lake → Review → Deploy (weekly)</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatDetectionArchitecture;