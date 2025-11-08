from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import numpy as np
import time
import os
from datetime import datetime

# Import models
from model1_detector import EnhancedPatternDetector
from model2_feature_extractor import UniversalFeatureExtractor
from model3_xgboost import UltimateXGBoostDetector

app = Flask(__name__, static_folder='../frontend/build', static_url_path='')
CORS(app)

# Initialize models
print("🔄 Initializing models...")
pattern_detector = EnhancedPatternDetector()
feature_extractor = UniversalFeatureExtractor()
ml_detector = UltimateXGBoostDetector()

# Try to load ML model
ml_model_loaded = False
try:
    if os.path.exists('models/model2_production.pkl'):
        ml_detector.load_model('models/model2_production.pkl')
        ml_model_loaded = True
        print("✅ ML Model loaded successfully")
    else:
        print("⚠️  ML Model not found - Only Pattern Detector will work")
except Exception as e:
    print(f"⚠️  ML Model load failed: {e}")

@app.route('/')
def serve_frontend():
    """Serve React frontend"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Main analysis endpoint"""
    try:
        data = request.get_json()
        input_text = data.get('input', '')
        
        if not input_text:
            return jsonify({'error': 'No input provided'}), 400
        
        start_time = time.time()
        
        # MODEL 1: Pattern Detection
        model1_result = pattern_detector.analyze(input_text)
        
        # MODEL 2: ML Prediction
        if ml_model_loaded:
            try:
                features = feature_extractor.extract_features(input_text)
                model2_result = ml_detector.predict_single(features)
            except Exception as e:
                print(f"ML prediction error: {e}")
                model2_result = {
                    'attack_type': 'UNKNOWN',
                    'confidence': 0,
                    'server_risk': 0,
                    'user_risk': 0,
                    'severity': 'none',
                    'error': str(e)
                }
        else:
            model2_result = {
                'attack_type': 'MODEL_NOT_LOADED',
                'confidence': 0,
                'server_risk': 0,
                'user_risk': 0,
                'severity': 'none',
                'note': 'ML model not available'
            }
        
        total_time = time.time() - start_time
        
        response = {
            'success': True,
            'input': input_text[:200],  # Limit for display
            'model1': {
                'verdict': model1_result['verdict'],
                'risk_score': model1_result['risk_score'],
                'confidence': model1_result['confidence'],
                'threats_detected': model1_result['threats_detected'],
                'detection_time_ms': model1_result['detection_time_ms']
            },
            'model2': {
                'attack_type': model2_result.get('attack_type', 'UNKNOWN'),
                'confidence': model2_result.get('confidence', 0),
                'server_risk': model2_result.get('server_risk', 0),
                'user_risk': model2_result.get('user_risk', 0),
                'severity': model2_result.get('severity', 'none')
            },
            'total_time_ms': round(total_time * 1000, 2),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error in analysis: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze():
    """Batch analysis endpoint"""
    try:
        data = request.get_json()
        inputs = data.get('inputs', [])
        
        if not inputs or len(inputs) == 0:
            return jsonify({'error': 'No inputs provided'}), 400
        
        if len(inputs) > 100:
            return jsonify({'error': 'Maximum 100 inputs allowed'}), 400
        
        results = []
        
        for input_text in inputs:
            try:
                # Model 1
                model1_result = pattern_detector.analyze(input_text)
                
                # Model 2
                if ml_model_loaded:
                    features = feature_extractor.extract_features(input_text)
                    model2_result = ml_detector.predict_single(features)
                else:
                    model2_result = {'attack_type': 'UNKNOWN', 'confidence': 0}
                
                results.append({
                    'input': input_text[:100],
                    'model1_verdict': model1_result['verdict'],
                    'model1_score': model1_result['risk_score'],
                    'model2_attack': model2_result.get('attack_type', 'UNKNOWN'),
                    'model2_confidence': model2_result.get('confidence', 0),
                    'severity': model2_result.get('severity', 'none')
                })
            except Exception as e:
                results.append({
                    'input': input_text[:100],
                    'error': str(e)
                })
                continue
        
        return jsonify({
            'success': True,
            'total_analyzed': len(results),
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model1_loaded': pattern_detector is not None,
        'model2_loaded': ml_model_loaded,
        'patterns_count': pattern_detector._count_patterns() if pattern_detector else 0,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/stats', methods=['GET'])
def stats():
    """System statistics"""
    return jsonify({
        'model1': {
            'name': 'Pattern Detector',
            'version': pattern_detector.patterns_version if pattern_detector else 'unknown',
            'patterns': pattern_detector._count_patterns() if pattern_detector else 0,
            'analyses': pattern_detector.analysis_count if pattern_detector else 0
        },
        'model2': {
            'name': 'XGBoost Classifier',
            'loaded': ml_model_loaded,
            'version': ml_detector.version if ml_model_loaded else 'N/A',
            'accuracy': f"{ml_detector.training_accuracy*100:.2f}%" if ml_model_loaded and ml_detector.training_accuracy else 'N/A'
        }
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Threat Detection System API Server")
    print("="*60)
    print(f"✅ Model 1 (Pattern Detector): Active")
    print(f"{'✅' if ml_model_loaded else '⚠️ '} Model 2 (ML Classifier): {'Active' if ml_model_loaded else 'Inactive'}")
    print(f"🌐 Server starting on http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5001)