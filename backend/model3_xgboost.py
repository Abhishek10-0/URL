import numpy as np
import pandas as pd
import pickle
import json
import time
import csv
import codecs
import glob
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# XGBoost and scikit-learn imports
try:
    import xgboost as xgb
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (accuracy_score, precision_recall_fscore_support,
                                 classification_report, confusion_matrix)
    from sklearn.preprocessing import LabelEncoder
except ImportError:
    print("⚠️  Missing dependencies! Install with:")
    print("   pip install xgboost scikit-learn pandas numpy")
    exit(1)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def clean_column_name(col_name: str) -> str:
    """Clean column name: strip whitespace, remove BOM, lowercase"""
    if not col_name:
        return ""
    col_name = col_name.replace('\ufeff', '')
    col_name = col_name.replace('\ufffe', '')
    col_name = col_name.replace('\u200b', '')
    col_name = col_name.strip().lower()
    return col_name


def detect_file_encoding(file_path: str) -> str:
    """Auto-detect file encoding with BOM handling"""
    try:
        with open(file_path, 'rb') as f:
            raw = f.read(4)
    except:
        return 'utf-8'

    if raw.startswith(codecs.BOM_UTF32_BE):
        return 'utf-32-be'
    elif raw.startswith(codecs.BOM_UTF32_LE):
        return 'utf-32-le'
    elif raw.startswith(codecs.BOM_UTF16_BE):
        return 'utf-16-be'
    elif raw.startswith(codecs.BOM_UTF16_LE):
        return 'utf-16-le'
    elif raw.startswith(codecs.BOM_UTF8):
        return 'utf-8-sig'

    encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'iso-8859-1', 'cp1252', 'utf-16']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                f.read()
            return encoding
        except (UnicodeDecodeError, UnicodeError):
            continue

    return 'utf-8'


def find_label_column(cleaned_fieldnames: List[str]) -> Optional[str]:
    """Find label column from cleaned fieldnames"""
    possible_names = ['label', 'attack_type', 'expected_attack', 'class',
                     'type', 'category', 'target', 'output', 'attack']

    for name in possible_names:
        if name in cleaned_fieldnames:
            return name

    return None


def normalize_label(label: str) -> str:
    """
    Normalize label to standard attack type
    FIXED: Now properly handles all variations
    """
    if not label:
        return 'BENIGN'

    label = str(label).strip().upper()

    # Label mapping - comprehensive
    label_map = {
        # SQL Injection variants
        'SQLI': 'SQL_INJECTION',
        'SQL': 'SQL_INJECTION',
        'SQL INJ': 'SQL_INJECTION',
        'SQL_INJ': 'SQL_INJECTION',
        'SQLINJECTION': 'SQL_INJECTION',
        'SQL INJECTION': 'SQL_INJECTION',

        # XSS variants
        'CROSS_SITE_SCRIPTING': 'XSS',
        'CROSS SITE SCRIPTING': 'XSS',
        'CROSSSITESCRIPTING': 'XSS',
        'CROSS-SITE SCRIPTING': 'XSS',

        # Command Injection variants
        'CMD_INJECTION': 'COMMAND_INJECTION',
        'CMD': 'COMMAND_INJECTION',
        'COMMAND': 'COMMAND_INJECTION',
        'OS_COMMAND': 'COMMAND_INJECTION',
        'COMMANDINJECTION': 'COMMAND_INJECTION',

        # Path Traversal variants
        'PATH': 'PATH_TRAVERSAL',
        'DIRECTORY_TRAVERSAL': 'PATH_TRAVERSAL',
        'DIR_TRAVERSAL': 'PATH_TRAVERSAL',
        'PATHTRAVERSAL': 'PATH_TRAVERSAL',

        # Redirect variants
        'REDIRECT': 'OPEN_REDIRECT',
        'OPENREDIRECT': 'OPEN_REDIRECT',
        'OPEN REDIRECT': 'OPEN_REDIRECT',

        # File Inclusion variants
        'LFI': 'LFI_RFI',
        'RFI': 'LFI_RFI',
        'FILE_INCLUSION': 'LFI_RFI',
        'LOCAL FILE INCLUSION': 'LFI_RFI',
        'REMOTE FILE INCLUSION': 'LFI_RFI',

        # LDAP variants
        'LDAP': 'LDAP_INJECTION',
        'LDAPINJECTION': 'LDAP_INJECTION',

        # NoSQL variants
        'NOSQL': 'NOSQL_INJECTION',
        'NO_SQL': 'NOSQL_INJECTION',
        'NOSQLINJECTION': 'NOSQL_INJECTION',

        # XXE variants
        'XXE': 'XXE_INJECTION',
        'XML': 'XXE_INJECTION',
        'XXEINJECTION': 'XXE_INJECTION',
        'XML EXTERNAL ENTITY': 'XXE_INJECTION',

        # CRLF variants
        'CRLF': 'CRLF_INJECTION',
        'CRLFINJECTION': 'CRLF_INJECTION',
        'HTTP_RESPONSE_SPLITTING': 'CRLF_INJECTION',

        # Phishing variants
        'PHISH': 'PHISHING',
        'PHISHING ATTACK': 'PHISHING',

        # Benign variants
        'CLEAN': 'BENIGN',
        'NORMAL': 'BENIGN',
        'SAFE': 'BENIGN',
        'LEGITIMATE': 'BENIGN',
        'NOT_ATTACK': 'BENIGN',
        'NOT ATTACK': 'BENIGN',
        '0': 'BENIGN',
        '0.0': 'BENIGN',
        'FALSE': 'BENIGN',

        # Generic attack indicators (map to 'ATTACK')
        '1': 'ATTACK',
        '1.0': 'ATTACK',
        'TRUE': 'ATTACK',
        'MALICIOUS': 'ATTACK',
        'ANOMALY': 'ATTACK',
        'SUSPICIOUS': 'ATTACK'
    }

    return label_map.get(label, label)


# =============================================================================
# ULTIMATE MODEL 2 CLASS
# =============================================================================

class UltimateXGBoostDetector:
    """
    Model 2: Ultimate XGBoost detector - FIXED VERSION
    Handles ALL edge cases and CSV formats
    """

    # Attack type definitions with risk profiles (FIXED: Added ATTACK)
    ATTACK_TYPES = {
        'BENIGN': {'user_risk': 0, 'server_risk': 0, 'severity': 'none'},
        'ATTACK': {'user_risk': 50, 'server_risk': 50, 'severity': 'medium'},  # Generic attack
        'SQL_INJECTION': {'user_risk': 20, 'server_risk': 95, 'severity': 'critical'},
        'XSS': {'user_risk': 85, 'server_risk': 40, 'severity': 'high'},
        'PATH_TRAVERSAL': {'user_risk': 30, 'server_risk': 90, 'severity': 'critical'},
        'COMMAND_INJECTION': {'user_risk': 25, 'server_risk': 100, 'severity': 'critical'},
        'PHISHING': {'user_risk': 100, 'server_risk': 10, 'severity': 'critical'},
        'OPEN_REDIRECT': {'user_risk': 75, 'server_risk': 30, 'severity': 'medium'},
        'LFI_RFI': {'user_risk': 40, 'server_risk': 95, 'severity': 'critical'},
        'LDAP_INJECTION': {'user_risk': 20, 'server_risk': 85, 'severity': 'high'},
        'NOSQL_INJECTION': {'user_risk': 20, 'server_risk': 90, 'severity': 'critical'},
        'XXE_INJECTION': {'user_risk': 30, 'server_risk': 90, 'severity': 'critical'},
        'CRLF_INJECTION': {'user_risk': 50, 'server_risk': 70, 'severity': 'high'}
    }

    def __init__(self, model_path: str = 'model2_production.pkl'):
        """Initialize detector"""
        self.model = None
        self.label_encoder = None
        self.model_path = model_path
        self.version = "2.1"
        self.trained_date = None
        self.feature_names = None
        self.training_accuracy = None
        self.training_samples = 0
        self.class_names = list(self.ATTACK_TYPES.keys())

        # XGBoost hyperparameters
        self.params = {
            'objective': 'multi:softmax',
            'num_class': len(self.class_names),
            'max_depth': 7,
            'learning_rate': 0.1,
            'n_estimators': 200,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'min_child_weight': 3,
            'gamma': 0.1,
            'random_state': 42,
            'n_jobs': -1,
            'eval_metric': 'mlogloss'
        }

    def load_single_csv(self, csv_file: str) -> Tuple[Optional[np.ndarray], Optional[np.ndarray], str]:
        """
        Load training data from single CSV file (ULTIMATE COMPATIBILITY)
        """
        encoding = detect_file_encoding(csv_file)

        try:
            with open(csv_file, 'r', encoding=encoding, errors='replace') as f:
                csv_reader = csv.DictReader(f)

                # Clean fieldnames
                original_fieldnames = list(csv_reader.fieldnames)
                cleaned_fieldnames = [clean_column_name(col) for col in csv_reader.fieldnames]
                cleaned_to_original = dict(zip(cleaned_fieldnames, original_fieldnames))

                # Find label column
                label_column_cleaned = find_label_column(cleaned_fieldnames)

                if not label_column_cleaned:
                    print(f"   ⚠️  No label column found in {Path(csv_file).name}")
                    return None, None, "no_label"

                label_column_original = cleaned_to_original[label_column_cleaned]

                # Get feature columns (all except label)
                feature_columns_original = [col for col in original_fieldnames
                                          if col != label_column_original]

                # Read data
                X_list = []
                y_list = []
                skipped = 0

                for row_num, row in enumerate(csv_reader, start=2):
                    try:
                        # Extract features
                        features = []
                        for col in feature_columns_original:
                            val = row.get(col, '0').strip()
                            try:
                                features.append(float(val))
                            except:
                                features.append(0.0)

                        # Ensure 120 features
                        if len(features) < 120:
                            features.extend([0.0] * (120 - len(features)))
                        elif len(features) > 120:
                            features = features[:120]

                        # Extract and normalize label
                        label = row.get(label_column_original, '').strip()
                        normalized_label = normalize_label(label)

                        # Validate label
                        if normalized_label not in self.ATTACK_TYPES:
                            skipped += 1
                            if skipped <= 5:  # Show first 5 unknown labels
                                print(f"   ⚠️  Row {row_num}: Unknown label '{label}' → Skipped")
                            continue

                        X_list.append(features)
                        y_list.append(normalized_label)

                    except Exception as e:
                        skipped += 1
                        continue

                if not X_list:
                    print(f"   ❌ No valid data extracted")
                    return None, None, "no_data"

                X = np.array(X_list, dtype=np.float32)
                y = np.array(y_list)

                if skipped > 5:
                    print(f"   ⚠️  Total skipped: {skipped} rows (unknown/invalid labels)")

                return X, y, "success"

        except Exception as e:
            print(f"   ❌ Error loading {Path(csv_file).name}: {str(e)[:80]}")
            import traceback
            traceback.print_exc()
            return None, None, "error"

    def load_training_data_from_folder(self, folder_path: str) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        """Load and combine multiple CSV files from folder"""
        print(f"\n{'='*95}")
        print(f"📂 LOADING TRAINING DATA FROM FOLDER: {folder_path}")
        print(f"{'='*95}\n")

        folder = Path(folder_path)
        if not folder.exists():
            print(f"❌ Folder not found: {folder_path}")
            return None, None

        # Find all CSV files
        csv_files = list(folder.glob("*.csv"))

        if not csv_files:
            print(f"❌ No CSV files found in {folder_path}")
            return None, None

        print(f"✅ Found {len(csv_files)} CSV files\n")

        # Load each file
        all_X = []
        all_y = []
        successful = 0
        failed = 0

        for csv_file in csv_files:
            print(f"📄 Loading: {csv_file.name}")

            X, y, status = self.load_single_csv(str(csv_file))

            if status == "success" and X is not None:
                all_X.append(X)
                all_y.append(y)
                successful += 1
                print(f"   ✅ Loaded {len(X)} samples\n")
            else:
                failed += 1
                print(f"   ❌ Failed: {status}\n")

        if not all_X:
            print(f"\n❌ No data loaded from any file!")
            return None, None

        # Combine all data
        X_combined = np.vstack(all_X)
        y_combined = np.concatenate(all_y)

        print(f"\n{'='*95}")
        print(f"📊 COMBINED DATA SUMMARY")
        print(f"{'='*95}")
        print(f"Files processed: {successful} successful, {failed} failed")
        print(f"Total samples: {len(X_combined):,}")
        print(f"Features: {X_combined.shape[1]}")

        # Class distribution
        unique, counts = np.unique(y_combined, return_counts=True)
        print(f"\n📊 Class Distribution:")
        for class_name, count in zip(unique, counts):
            percentage = (count / len(y_combined) * 100)
            print(f"   {class_name:20s}: {count:6d} ({percentage:5.1f}%)")

        print(f"{'='*95}\n")

        return X_combined, y_combined

    def load_training_data_from_csv(self, csv_file: str) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        """Load training data from single CSV file"""
        print(f"\n{'='*95}")
        print(f"📂 LOADING TRAINING DATA: {csv_file}")
        print(f"{'='*95}\n")

        X, y, status = self.load_single_csv(csv_file)

        if status == "success" and X is not None:
            print(f"\n✅ Loaded {len(X):,} samples from {Path(csv_file).name}")

            # Class distribution
            unique, counts = np.unique(y, return_counts=True)
            print(f"\n📊 Class Distribution:")
            for class_name, count in zip(unique, counts):
                percentage = (count / len(y) * 100)
                print(f"   {class_name:20s}: {count:6d} ({percentage:5.1f}%)")

            print(f"\n{'='*95}\n")
            return X, y
        else:
            print(f"❌ Failed to load data: {status}")
            return None, None

    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Dict:
        """Train XGBoost model"""
        print(f"\n{'='*95}")
        print(f"🎯 TRAINING MODEL 2 (XGBoost Multi-Class)")
        print(f"{'='*95}\n")

        start_time = time.time()

        # Encode labels
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        print(f"✅ Encoded {len(self.label_encoder.classes_)} classes:")
        for i, class_name in enumerate(self.label_encoder.classes_):
            print(f"   {i}: {class_name}")

        # Update num_class
        self.params['num_class'] = len(self.label_encoder.classes_)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=test_size, random_state=42, stratify=y_encoded
        )

        print(f"\n📊 Data Split:")
        print(f"   Training:   {len(X_train):,} samples ({(1-test_size)*100:.0f}%)")
        print(f"   Testing:    {len(X_test):,} samples ({test_size*100:.0f}%)")

        # Train XGBoost
        print(f"\n🔄 Training XGBoost model...")
        print(f"   This may take a while for large datasets...")

        self.model = xgb.XGBClassifier(**self.params)

        eval_set = [(X_test, y_test)]
        self.model.fit(X_train, y_train, eval_set=eval_set, verbose=False)

        training_time = time.time() - start_time

        # Evaluate
        print(f"\n✅ Training complete in {training_time:.2f}s")
        print(f"\n📈 EVALUATING MODEL PERFORMANCE...")

        y_train_pred = self.model.predict(X_train)
        y_test_pred = self.model.predict(X_test)

        train_accuracy = accuracy_score(y_train, y_train_pred)
        test_accuracy = accuracy_score(y_test, y_test_pred)

        print(f"\n🎯 Overall Accuracy:")
        print(f"   Training: {train_accuracy*100:.2f}%")
        print(f"   Testing:  {test_accuracy*100:.2f}%")

        # Per-class metrics
        print(f"\n📊 Per-Class Performance (Test Set):")
        print(f"{'Class':<20} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'Support':<10}")
        print(f"{' -'*70}")

        precision, recall, f1, support = precision_recall_fscore_support(
            y_test, y_test_pred, labels=range(len(self.label_encoder.classes_)), zero_division=0
        )

        for i, class_name in enumerate(self.label_encoder.classes_):
            print(f"{class_name:<20} {precision[i]*100:>10.1f}%  {recall[i]*100:>10.1f}%  "
                  f"{f1[i]*100:>10.1f}%  {support[i]:>8d}")

        # Save metadata
        self.trained_date = datetime.now()
        self.training_accuracy = test_accuracy
        self.training_samples = len(X)

        metrics = {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'training_time': training_time,
            'n_samples': len(X),
            'n_classes': len(self.label_encoder.classes_),
            'per_class_f1': dict(zip(self.label_encoder.classes_, f1))
        }

        print(f"\n{'='*95}")
        print(f"✅ MODEL TRAINING COMPLETE")
        print(f"{'='*95}\n")

        return metrics

    def predict_single(self, features: np.ndarray) -> Dict:
        """Predict single input (120 features) - FIXED"""
        if self.model is None:
            raise ValueError("Model not loaded! Train or load a model first.")

        start_time = time.time()

        try:
            # Ensure 2D array
            if features.ndim == 1:
                features = features.reshape(1, -1)

            # Validate
            if features.shape[1] != 120:
                raise ValueError(f"Expected 120 features, got {features.shape[1]}")

            # Predict
            proba = self.model.predict_proba(features)[0]
            predicted_class_idx = np.argmax(proba)
            predicted_class = str(self.label_encoder.inverse_transform([predicted_class_idx])[0])
            confidence = float(proba[predicted_class_idx])

            # All probabilities
            all_probabilities = {}
            for i, class_name in enumerate(self.label_encoder.classes_):
                all_probabilities[str(class_name)] = float(proba[i])

            # Risk assessment (with fallback for unknown types)
            if predicted_class in self.ATTACK_TYPES:
                risk_profile = self.ATTACK_TYPES[predicted_class]
            else:
                # Fallback for unknown attack types
                print(f"⚠️  Warning: Unknown attack type '{predicted_class}', using ATTACK defaults")
                risk_profile = self.ATTACK_TYPES['ATTACK']

            prediction_time = time.time() - start_time

            return {
                'attack_type': predicted_class,
                'confidence': confidence,
                'user_risk': risk_profile['user_risk'],
                'server_risk': risk_profile['server_risk'],
                'severity': risk_profile['severity'],
                'all_probabilities': all_probabilities,
                'prediction_time_ms': round(prediction_time * 1000, 2)
            }

        except Exception as e:
            print(f"❌ Prediction error: {e}")
            import traceback
            traceback.print_exc()
            raise

    def batch_predict_with_extractor(self, inputs: List[str], extractor=None, show_progress: bool = True) -> List[Dict]:
        """Batch prediction with Feature Extractor"""
        if extractor is None:
            try:
                from feature_extractor import UniversalFeatureExtractor
                extractor = UniversalFeatureExtractor()
            except ImportError:
                raise ImportError("feature_extractor.py not found!")

        results = []

        print(f"\n🔮 Batch Prediction: {len(inputs)} inputs")

        for i, input_data in enumerate(inputs):
            try:
                result = self.predict_with_extractor(input_data, extractor)
                results.append(result)

                if show_progress and (i + 1) % 100 == 0:
                    print(f"   Processed {i+1}/{len(inputs)}...")

            except Exception as e:
                print(f"   ⚠️  Error on input {i+1}: {str(e)[:50]}")
                continue

        print(f"✅ Complete: {len(results)}/{len(inputs)} successful\n")

        return results

    def save_model(self, path: str = None):
        """Save trained model"""
        if self.model is None:
            print("❌ No model to save!")
            return False

        if path is None:
            path = self.model_path if hasattr(self, 'model_path') and self.model_path else 'model2_production.pkl'

        model_data = {
            'model': self.model,
            'label_encoder': self.label_encoder,
            'version': self.version,
            'trained_date': self.trained_date.isoformat() if self.trained_date else None,
            'training_accuracy': self.training_accuracy,
            'training_samples': self.training_samples,
            'params': self.params,
            'class_names': self.class_names
        }

        try:
            with open(path, 'wb') as f:
                pickle.dump(model_data, f)

            file_size = Path(path).stat().st_size / (1024 * 1024)
            print(f"✅ Model saved to: {path}")
            print(f"   File size: {file_size:.2f} MB")
            print(f"   Version: {self.version}")
            print(f"   Samples trained: {self.training_samples:,}")
            return True
        except Exception as e:
            print(f"❌ Error saving model: {e}")
            return False

    def load_model(self, path: str = None):
        """Load trained model"""
        if path is None:
            path = self.model_path

        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)

            self.model = model_data['model']
            self.label_encoder = model_data['label_encoder']
            self.version = model_data.get('version', 'unknown')
            trained_date_str = model_data.get('trained_date')
            self.trained_date = datetime.fromisoformat(trained_date_str) if trained_date_str else None
            self.training_accuracy = model_data.get('training_accuracy')
            self.training_samples = model_data.get('training_samples', 0)
            self.params = model_data.get('params', self.params)
            self.class_names = model_data.get('class_names', self.class_names)

            print(f"✅ Model loaded from: {path}")
            print(f"   Version: {self.version}")
            print(f"   Trained: {self.trained_date.strftime('%Y-%m-%d %H:%M') if self.trained_date else 'Unknown'}")
            print(f"   Training accuracy: {self.training_accuracy*100:.2f}%" if self.training_accuracy else "   Accuracy: Unknown")
            print(f"   Samples trained on: {self.training_samples:,}")
            print(f"   Classes: {len(self.label_encoder.classes_)}")
            return True

        except FileNotFoundError:
            print(f"❌ Model file not found: {path}")
            return False
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            import traceback
            traceback.print_exc()
            return False

    def print_prediction(self, result: Dict):
        """Pretty print prediction"""
        attack_emojis = {
            'BENIGN': '🟢', 'ATTACK': '🟡', 'SQL_INJECTION': '🔴', 'XSS': '🟠',
            'PATH_TRAVERSAL': '🟡', 'COMMAND_INJECTION': '🔴', 'PHISHING': '🔴',
            'OPEN_REDIRECT': '🟠', 'LFI_RFI': '🔴', 'LDAP_INJECTION': '🟠',
            'NOSQL_INJECTION': '🔴', 'XXE_INJECTION': '🟠', 'CRLF_INJECTION': '🟠'
        }

        emoji = attack_emojis.get(result['attack_type'], '⚪')

        print("\n" + "="*95)
        print("🤖 MODEL 2: XGBoost PREDICTION")
        print("="*95)

        if 'input' in result:
            print(f"📌 Input: {result['input'][:80]}{'...' if len(result['input']) > 80 else ''}")

        print(f"\n{emoji} ATTACK TYPE: {result['attack_type']}")
        print(f"   Confidence: {result['confidence']*100:.1f}%")
        print(f"   Severity: {result['severity'].upper()}")

        print(f"\n⚠️  RISK ASSESSMENT:")
        user_bar = '█' * (result['user_risk']//10) + '░' * (10 - result['user_risk']//10)
        server_bar = '█' * (result['server_risk']//10) + '░' * (10 - result['server_risk']//10)
        print(f"   User Risk:   {result['user_risk']:3d}/100 [{user_bar}]")
        print(f"   Server Risk: {result['server_risk']:3d}/100 [{server_bar}]")

        # Top 3 predictions
        sorted_probs = sorted(result['all_probabilities'].items(),
                            key=lambda x: x[1], reverse=True)

        print(f"\n📊 Top Predictions:")
        for i, (attack_type, prob) in enumerate(sorted_probs[:3], 1):
            emoji = attack_emojis.get(attack_type, '⚪')
            bar_length = int(prob * 30)
            bar = '█' * bar_length + '░' * (30 - bar_length)
            print(f"   {i}. {emoji} {attack_type:20s} {bar} {prob*100:5.1f}%")

        print(f"\n⏱️  Prediction Time: {result['prediction_time_ms']}ms")
        print("="*95 + "\n")


# =============================================================================
# MAIN MENU
# =============================================================================

if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║   MODEL 2: Ultimate XGBoost Detector v2.1 (FIXED)                           ║
    ║   For Bidirectional Threat Intelligence Platform                             ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝

    🎯 FIXED IN v2.1:
    ✅ Added 'ATTACK' as generic attack type (no more KeyError)
    ✅ Improved error handling and robustness
    ✅ Better label normalization
    ✅ Handles 100k+ samples efficiently

    📊 WORKFLOW:
    1. Train: Load CSV/Folder → Train XGBoost → Save model
    2. Predict: Load model → Input features → Get attack type
    3. Integration: Input → Feature Extractor → Model 2 → Result
    """)

    detector = UltimateXGBoostDetector()

    while True:
        print("\n" + "="*95)
        print("MAIN MENU")
        print("="*95)
        print("1. Train model from CSV file")
        print("2. Train model from folder (multiple datasets)")
        print("3. Load existing model")
        print("4. Predict single input (with Feature Extractor)")
        print("5. Batch predict from list (with Feature Extractor)")
        print("6. Batch predict from CSV (features already extracted)")
        print("7. Show model info")
        print("8. Save current model")
        print("0. Exit")
        print("="*95)

        choice = input("\nEnter choice: ").strip()

        if choice == '1':
            csv_file = input("\n📂 Enter CSV file path: ").strip()
            if csv_file:
                X, y = detector.load_training_data_from_csv(csv_file)
                if X is not None:
                    metrics = detector.train(X, y)
                    save_choice = input("\n💾 Save trained model? (y/n): ").strip().lower()
                    if save_choice == 'y':
                        model_name = input("Model filename (Enter for 'model2_production.pkl'): ").strip()
                        detector.save_model(model_name if model_name else None)

        elif choice == '2':
            folder_path = input("\n📂 Enter folder path: ").strip()
            if folder_path:
                X, y = detector.load_training_data_from_folder(folder_path)
                if X is not None:
                    metrics = detector.train(X, y)
                    save_choice = input("\n💾 Save trained model? (y/n): ").strip().lower()
                    if save_choice == 'y':
                        model_name = input("Model filename (Enter for 'model2_production.pkl'): ").strip()
                        detector.save_model(model_name if model_name else None)

        elif choice == '3':
            model_path = input("\n📂 Enter model path (Enter for 'model2_production.pkl'): ").strip()
            detector.load_model(model_path if model_path else None)

        elif choice == '4':
            if detector.model is None:
                print("\n❌ No model loaded! Load or train a model first.")
                continue
            input_data = input("\nEnter URL/Payload/JSON: ").strip()
            if input_data:
                try:
                    result = detector.predict_with_extractor(input_data)
                    detector.print_prediction(result)
                except Exception as e:
                    print(f"\n❌ Error: {e}")

        elif choice == '5':
            if detector.model is None:
                print("\n❌ No model loaded!")
                continue
            print("\n💡 Enter inputs (one per line), press Enter twice when done:")
            inputs = []
            while True:
                line = input().strip()
                if not line:
                    break
                inputs.append(line)
            if inputs:
                results = detector.batch_predict_with_extractor(inputs)
                for i, result in enumerate(results, 1):
                    emoji = '🔴' if result['attack_type'] != 'BENIGN' else '🟢'
                    print(f"{i:3d}. {emoji} {result['attack_type']:20s} ({result['confidence']*100:5.1f}%)")

        elif choice == '6':
            if detector.model is None:
                print("\n❌ No model loaded!")
                continue
            csv_file = input("\n📂 Enter CSV file path: ").strip()
            if csv_file:
                try:
                    encoding = detect_file_encoding(csv_file)
                    df = pd.read_csv(csv_file, encoding=encoding)
                    print(f"✅ Loaded {len(df):,} samples")

                    has_labels = 'label' in df.columns
                    X = df.drop('label', axis=1).values if has_labels else df.values
                    y_true = df['label'].values if has_labels else None

                    if X.shape[1] != 120:
                        print(f"⚠️  Adjusting features from {X.shape[1]} to 120")
                        if X.shape[1] < 120:
                            X = np.hstack([X, np.zeros((X.shape[0], 120 - X.shape[1]))])
                        else:
                            X = X[:, :120]

                    print(f"🔮 Predicting {len(X):,} samples...")
                    predictions = []
                    for i, features in enumerate(X):
                        result = detector.predict_single(features)
                        predictions.append(result)
                        if (i + 1) % 1000 == 0:
                            print(f"   {i+1:,}/{len(X):,}...")

                    print(f"\n✅ Prediction complete!")

                    if has_labels:
                        pred_labels = [p['attack_type'] for p in predictions]
                        correct = sum(1 for p, t in zip(pred_labels, y_true) if p == normalize_label(t))
                        print(f"   Accuracy: {correct/len(y_true)*100:.2f}% ({correct:,}/{len(y_true):,})")

                except Exception as e:
                    print(f"❌ Error: {e}")

        elif choice == '7':
            if detector.model is None:
                print("\n❌ No model loaded!")
                continue
            print(f"\n{'='*95}")
            print("📊 MODEL INFORMATION")
            print(f"{'='*95}")
            print(f"Version: {detector.version}")
            print(f"Training accuracy: {detector.training_accuracy*100:.2f}%" if detector.training_accuracy else "Unknown")
            print(f"Training samples: {detector.training_samples:,}")
            print(f"Classes: {len(detector.label_encoder.classes_)}")
            print(f"\n📋 Attack Types:")
            for i, cls in enumerate(detector.label_encoder.classes_, 1):
                print(f"   {i:2d}. {cls}")
            print(f"{'='*95}")

        elif choice == '8':
            if detector.model is None:
                print("\n❌ No model to save!")
                continue
            model_path = input("\n💾 Model filename (Enter for 'model2_production.pkl'): ").strip()
            detector.save_model(model_path if model_path else None)

        elif choice == '0':
            print("\n👋 Goodbye!")
            break
        else:
            print("\n❌ Invalid choice!")
