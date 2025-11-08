# @title
import re
import json
import math
import csv
import codecs
import numpy as np
import pandas as pd
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import string


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


class UniversalFeatureExtractor:
    """
    Extracts 120 numerical features from any input type

    Feature Groups:
    - [0-39]   Universal Features (40) - Always extracted
    - [40-79]  URL Features (40) - Extracted if valid URL, else zeros
    - [80-119] Payload Features (40) - Always extracted
    """

    def __init__(self):
        """Initialize feature extractor with constants"""

        # Suspicious TLDs
        self.suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work',
            'click', 'link', 'pw', 'cc', 'info', 'biz'
        }

        # SQL keywords
        self.sql_keywords = {
            'select', 'union', 'insert', 'update', 'delete', 'drop',
            'create', 'alter', 'exec', 'execute', 'cast', 'convert',
            'declare', 'table', 'from', 'where', 'or', 'and', 'order',
            'group', 'having', 'join', 'inner', 'outer', 'into'
        }

        # XSS keywords
        self.xss_keywords = {
            'script', 'alert', 'prompt', 'confirm', 'eval', 'onerror',
            'onload', 'onclick', 'onmouseover', 'javascript', 'iframe',
            'img', 'svg', 'body', 'object', 'embed', 'applet'
        }

        # Command injection keywords
        self.cmd_keywords = {
            'cat', 'ls', 'dir', 'rm', 'wget', 'curl', 'chmod', 'kill',
            'bash', 'sh', 'nc', 'netcat', 'whoami', 'id', 'uname', 'pwd'
        }

        # Suspicious ports
        self.suspicious_ports = {
            1337, 31337, 8080, 8888, 4444, 5555, 6666, 7777, 9999,
            3389, 5900, 5901
        }

    def extract_features(self, input_data: str) -> np.ndarray:
        """
        Extract all 120 features from input

        Args:
            input_data: String (URL/Payload/JSON)

        Returns:
            numpy array of shape (120,) with all features
        """
        input_type = self._detect_input_type(input_data)

        universal_features = self._extract_universal_features(input_data)

        if input_type == 'url':
            url_features = self._extract_url_features(input_data)
        else:
            url_features = np.zeros(40)

        payload_features = self._extract_payload_features(input_data)

        all_features = np.concatenate([
            universal_features,
            url_features,
            payload_features
        ])

        return all_features

    def _detect_input_type(self, input_data: str) -> str:
        """Detect if input is URL, JSON, or raw payload"""
        input_data = input_data.strip()

        if (input_data.startswith('{') and input_data.endswith('}')) or \
           (input_data.startswith('[') and input_data.endswith(']')):
            try:
                json.loads(input_data)
                return 'json'
            except:
                pass

        if input_data.startswith(('http://', 'https://', 'ftp://', 'file://')):
            return 'url'

        if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/|$)', input_data):
            return 'url'

        return 'payload'

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string"""
        if not data:
            return 0.0

        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1

        length = len(data)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _extract_universal_features(self, input_data: str) -> np.ndarray:
        """Extract 40 universal features (always extracted)"""
        features = []

        data_lower = input_data.lower()
        length = len(input_data)

        # [0] Total length
        features.append(length)

        # [1] Entropy
        features.append(self._calculate_entropy(input_data))

        # [2-6] Character type ratios
        if length > 0:
            features.append(sum(c.isalpha() for c in input_data) / length)  # [2]
            features.append(sum(c.isdigit() for c in input_data) / length)  # [3]
            features.append(sum(c in string.punctuation for c in input_data) / length)  # [4]
            features.append(sum(c.isupper() for c in input_data) / length)  # [5]
            features.append(sum(c.isspace() for c in input_data) / length)  # [6]
        else:
            features.extend([0, 0, 0, 0, 0])

        # [7-11] Specific character ratios
        if length > 0:
            features.append(input_data.count("'") / length)     # [7]
            features.append(input_data.count('"') / length)     # [8]
            features.append(input_data.count('<') / length)     # [9]
            features.append(input_data.count('>') / length)     # [10]
            features.append(input_data.count('=') / length)     # [11]
        else:
            features.extend([0, 0, 0, 0, 0])

        # [12-20] Special character counts
        features.append(input_data.count(';'))          # [12]
        features.append(input_data.count('&'))          # [13]
        features.append(input_data.count('|'))          # [14]
        features.append(input_data.count('('))          # [15]
        features.append(input_data.count(')'))          # [16]
        features.append(input_data.count('['))          # [17]
        features.append(input_data.count(']'))          # [18]
        features.append(input_data.count('{'))          # [19]
        features.append(input_data.count('}'))          # [20]

        # [21] URL encoding indicators
        url_encoded = len(re.findall(r'%[0-9a-fA-F]{2}', input_data))
        features.append(url_encoded)

        # [22] Hex encoding indicators
        hex_encoded = len(re.findall(r'0x[0-9a-fA-F]+', input_data))
        features.append(hex_encoded)

        # [23-27] Keyword presence (binary)
        features.append(1 if any(kw in data_lower for kw in self.sql_keywords) else 0)  # [23]
        features.append(1 if any(kw in data_lower for kw in self.xss_keywords) else 0)  # [24]
        features.append(1 if any(kw in data_lower for kw in self.cmd_keywords) else 0)  # [25]
        features.append(1 if 'script' in data_lower else 0)                             # [26]
        features.append(1 if 'javascript:' in data_lower else 0)                        # [27]

        # [28] SQL comment indicators
        sql_comments = (
            input_data.count('--') +
            input_data.count('#') +
            input_data.count('/*') +
            input_data.count('*/')
        )
        features.append(sql_comments)

        # [29-32] Path traversal indicators
        features.append(input_data.count('../'))        # [29]
        features.append(input_data.count('..\\'))       # [30]
        features.append(1 if 'etc/passwd' in data_lower else 0)      # [31]
        features.append(1 if 'windows' in data_lower and 'system' in data_lower else 0)  # [32]

        # [33] Command injection indicators
        cmd_separators = input_data.count(';') + input_data.count('|') + input_data.count('&')
        features.append(cmd_separators)

        # [34-36] Token statistics
        tokens = input_data.split()
        features.append(len(tokens))                    # [34]
        features.append(max(len(t) for t in tokens) if tokens else 0)  # [35]
        features.append(sum(len(t) for t in tokens) / len(tokens) if tokens else 0)  # [36]

        # [37] Consecutive repeated characters
        max_repeat = 0
        current_repeat = 1
        for i in range(1, length):
            if input_data[i] == input_data[i-1]:
                current_repeat += 1
                max_repeat = max(max_repeat, current_repeat)
            else:
                current_repeat = 1
        features.append(max_repeat)

        # [38] Character diversity
        unique_chars = len(set(input_data))
        features.append(unique_chars / length if length > 0 else 0)

        # [39] Contains suspicious patterns (binary) - FIXED LOGIC
        suspicious = 0
        if re.search(r"('\s*or\s*')", data_lower):
            suspicious = 1
        elif re.search(r"<script", data_lower):
            suspicious = 1
        elif re.search(r"\.\./", input_data):
            suspicious = 1
        elif re.search(r";\s*(cat|ls|rm|wget)", data_lower):
            suspicious = 1
        features.append(suspicious)

        return np.array(features, dtype=np.float32)

    def _extract_url_features(self, url: str) -> np.ndarray:
        """Extract 40 URL-specific features"""
        features = []

        try:
            parsed = urlparse(url)

            scheme_map = {'http': 0, 'https': 1, 'ftp': 2}
            features.append(scheme_map.get(parsed.scheme, 3))

            domain = parsed.netloc.split(':')[0]
            features.append(len(domain))
            features.append(domain.count('.'))
            features.append(1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0)
            features.append(1 if '-' in domain else 0)
            features.append(1 if domain.count('.') > 3 else 0)

            tld = domain.split('.')[-1] if '.' in domain else ''
            features.append(1 if tld in self.suspicious_tlds else 0)

            port = parsed.port if parsed.port else (443 if parsed.scheme == 'https' else 80)
            features.append(port)
            features.append(1 if port in self.suspicious_ports else 0)
            features.append(1 if port != 80 and port != 443 else 0)
            features.append(1 if ':' in parsed.netloc else 0)

            path = parsed.path
            features.append(len(path))
            features.append(path.count('/'))
            features.append(1 if '..' in path else 0)
            features.append(1 if path.endswith('.php') or path.endswith('.asp') or path.endswith('.jsp') else 0)
            features.append(path.count('.'))

            query = parsed.query
            features.append(len(query))
            params = parse_qs(query, keep_blank_values=True)
            features.append(len(params))

            param_name_lengths = [len(k) for k in params.keys()]
            features.append(sum(param_name_lengths) / len(param_name_lengths) if param_name_lengths else 0)

            param_value_lengths = [len(v[0]) for v in params.values() if v]
            features.append(sum(param_value_lengths) / len(param_value_lengths) if param_value_lengths else 0)

            all_values = ''.join([v[0] for v in params.values() if v])
            features.append(1 if "'" in all_values else 0)
            features.append(1 if '<' in all_values else 0)
            features.append(1 if ';' in all_values else 0)
            features.append(all_values.count('%') / len(all_values) if all_values else 0)

            fragment = parsed.fragment
            features.append(len(fragment))
            features.append(1 if fragment else 0)
            features.append(1 if '<script' in fragment.lower() else 0)
            features.append(1 if 'javascript:' in fragment.lower() else 0)
            features.append(fragment.count('%') / len(fragment) if fragment else 0)

            features.append(self._calculate_entropy(url))
            features.append(self._calculate_entropy(domain))
            features.append(self._calculate_entropy(path))
            features.append(self._calculate_entropy(query))
            features.append(len(url))

            features.append(1 if '@' in parsed.netloc else 0)
            features.append(1 if url.count('//') > 1 else 0)
            features.append(1 if 'admin' in url.lower() else 0)
            features.append(1 if 'login' in url.lower() else 0)
            features.append(1 if 'redirect' in url.lower() or 'goto' in url.lower() else 0)
            features.append(1 if len(url) > 200 else 0)

        except Exception as e:
            features = [0] * 40

        return np.array(features, dtype=np.float32)

    def _extract_payload_features(self, input_data: str) -> np.ndarray:
        """Extract 40 payload-specific features"""
        features = []

        data_lower = input_data.lower()
        length = len(input_data)

        features.append(input_data.count("'"))
        features.append(input_data.count('"'))
        features.append(input_data.count('`'))
        single_double_ratio = input_data.count("'") / (input_data.count('"') + 1)
        features.append(single_double_ratio)
        features.append(1 if "'" in input_data and '"' in input_data else 0)

        features.append(input_data.count('(') - input_data.count(')'))
        features.append(input_data.count('[') - input_data.count(']'))
        features.append(input_data.count('{') - input_data.count('}'))
        features.append(input_data.count('(') + input_data.count('['))
        features.append(input_data.count(')') + input_data.count(']'))

        features.append(len(re.findall(r'\s+(or|and)\s+', data_lower, re.IGNORECASE)))
        features.append(data_lower.count('union'))
        features.append(data_lower.count('select'))
        features.append(len(re.findall(r"'\s*=\s*'", input_data)))
        features.append(len(re.findall(r'\d+\s*=\s*\d+', input_data)))

        features.append(1 if re.search(r'<\w+.*?>', input_data) else 0)
        features.append(data_lower.count('script'))
        features.append(len(re.findall(r'on\w+\s*=', data_lower)))
        features.append(1 if 'javascript:' in data_lower else 0)
        features.append(1 if '<iframe' in data_lower or '<img' in data_lower or '<svg' in data_lower else 0)

        features.append(len(re.findall(r'[;&|]', input_data)))
        features.append(1 if '$((' in input_data or '`' in input_data else 0)
        features.append(data_lower.count('cat') + data_lower.count('wget') + data_lower.count('curl'))
        features.append(1 if '/bin/' in data_lower or '/usr/bin/' in data_lower else 0)
        features.append(len(re.findall(r'%0a|%0d', data_lower)))

        features.append(input_data.count('../') + input_data.count('..\\'))
        features.append(1 if 'etc/passwd' in data_lower or 'etc/shadow' in data_lower else 0)
        features.append(1 if 'system32' in data_lower else 0)
        features.append(len(re.findall(r'%2e%2e', data_lower)))
        features.append(1 if re.search(r'\.\.[/\\]', input_data) else 0)

        features.append(len(re.findall(r'\\x[0-9a-fA-F]{2}', input_data)))
        features.append(len(re.findall(r'\\u[0-9a-fA-F]{4}', input_data)))
        features.append(len(re.findall(r'&#\d+;', input_data)))
        features.append(1 if 'eval(' in data_lower or 'exec(' in data_lower else 0)
        features.append(len(re.findall(r'fromCharCode|atob|btoa', data_lower)))

        features.append(1 if re.search(r'<\?php', data_lower) else 0)
        features.append(1 if 'base64' in data_lower else 0)
        features.append(len(re.findall(r'\$\w+', input_data)))
        features.append(1 if length > 500 else 0)
        features.append(len(re.findall(r'<!--.*?-->', input_data)))

        return np.array(features, dtype=np.float32)

    def get_feature_names(self) -> List[str]:
        """Return list of all 120 feature names"""
        return [
            "length", "entropy", "alpha_ratio", "digit_ratio", "special_ratio",
            "uppercase_ratio", "whitespace_ratio", "single_quote_ratio", "double_quote_ratio",
            "less_than_ratio", "greater_than_ratio", "equals_ratio", "semicolon_count",
            "ampersand_count", "pipe_count", "open_paren_count", "close_paren_count",
            "open_bracket_count", "close_bracket_count", "open_brace_count", "close_brace_count",
            "url_encoded_count", "hex_encoded_count", "has_sql_keywords", "has_xss_keywords",
            "has_cmd_keywords", "has_script_tag", "has_javascript_protocol", "sql_comment_count",
            "relative_path_count", "windows_path_count", "has_etc_passwd", "has_windows_system",
            "cmd_separators", "token_count", "max_token_length", "avg_token_length",
            "max_consecutive_repeat", "char_diversity", "has_suspicious_patterns",

            "url_scheme", "domain_length", "subdomain_count", "is_ip_address", "has_hyphen",
            "too_many_subdomains", "suspicious_tld", "port_number", "suspicious_port",
            "non_standard_port", "port_explicit", "path_length", "path_depth",
            "has_path_traversal", "is_dynamic_page", "dots_in_path", "query_length",
            "param_count", "avg_param_name_length", "avg_param_value_length",
            "single_quote_in_values", "less_than_in_values", "semicolon_in_values",
            "url_encoding_ratio_values", "fragment_length", "has_fragment",
            "script_in_fragment", "js_in_fragment", "encoding_in_fragment",
            "url_entropy", "domain_entropy", "path_entropy", "query_entropy",
            "total_url_length", "has_at_symbol", "multiple_slashes", "has_admin",
            "has_login", "has_redirect", "unusually_long_url",

            "single_quote_count", "double_quote_count", "backtick_count",
            "single_double_quote_ratio", "mixed_quotes", "paren_imbalance",
            "bracket_imbalance", "brace_imbalance", "total_opening", "total_closing",
            "logical_operators", "union_keyword", "select_keyword", "quote_equals_quote",
            "number_equals_number", "has_html_tags", "script_keyword", "event_handlers",
            "js_protocol", "dangerous_tags", "command_separators", "command_substitution",
            "dangerous_commands", "binary_paths", "crlf_injection", "traversal_sequences",
            "sensitive_files", "windows_system", "encoded_traversal", "traversal_pattern",
            "hex_encoding", "unicode_encoding", "html_entities", "eval_functions",
            "js_encoding_functions", "php_tags", "base64_keyword", "variable_references",
            "very_long_payload", "html_comments"
        ]

    def batch_extract_from_csv(self, csv_file_path: str, output_file: str = None) -> Optional[pd.DataFrame]:
        """
        Extract features from CSV file in batch

        Args:
            csv_file_path: Input CSV with columns: 'input' or 'payload' or 'url', and 'label'
            output_file: Output CSV filename (default: input_filename_features.csv)

        Returns:
            DataFrame with 120 features + label column
        """
        print(f"\n{'='*95}")
        print(f"📂 BATCH FEATURE EXTRACTION: {csv_file_path}")
        print(f"{'='*95}\n")

        # Detect encoding
        encoding = detect_file_encoding(csv_file_path)
        print(f"✅ Detected encoding: {encoding}\n")

        try:
            with open(csv_file_path, 'r', encoding=encoding, errors='replace') as file:
                csv_reader = csv.DictReader(file)

                # Clean fieldnames
                original_fieldnames = list(csv_reader.fieldnames)
                cleaned_fieldnames = [clean_column_name(col) for col in csv_reader.fieldnames]
                fieldname_mapping = dict(zip(cleaned_fieldnames, original_fieldnames))

                print(f"📋 Found columns: {', '.join(original_fieldnames)}\n")

                # Find input column
                input_column_cleaned = None
                for col in cleaned_fieldnames:
                    if col in ['url', 'payload', 'input', 'data']:
                        input_column_cleaned = col
                        break

                if not input_column_cleaned:
                    print("❌ Error: CSV must have 'url', 'payload', 'input', or 'data' column!")
                    return None

                input_column_original = fieldname_mapping[input_column_cleaned]

                # Find label column
                label_column_cleaned = None
                for col in cleaned_fieldnames:
                    if col in ['label', 'attack_type', 'class']:
                        label_column_cleaned = col
                        break

                has_labels = label_column_cleaned is not None
                label_column_original = fieldname_mapping.get(label_column_cleaned) if has_labels else None

                print(f"✅ Input column: '{input_column_original}'")
                if has_labels:
                    print(f"✅ Label column: '{label_column_original}'")
                else:
                    print(f"ℹ️  No label column found (features will be extracted without labels)")

                print(f"\n🔄 Extracting features...\n")

                # Extract features for each row
                all_features = []
                all_labels = []
                skipped = 0

                for row_num, row in enumerate(csv_reader, start=2):
                    input_data_raw = row.get(input_column_original) # Get raw value first
                    input_data = str(input_data_raw).strip() if input_data_raw is not None else ''

                    if not input_data:
                        skipped += 1
                        continue

                    try:
                        features = self.extract_features(input_data)

                        current_row_label = None # Initialize current_row_label
                        if has_labels:
                            label_value = row.get(label_column_original) # Get raw label value
                            current_row_label = str(label_value).strip() if label_value is not None else ''

                        # Only append to lists if both features and (if applicable) labels are successfully processed
                        all_features.append(features)
                        if has_labels:
                            all_labels.append(current_row_label)

                        if row_num % 100 == 0:
                            print(f"   Processed {row_num-1} rows...")

                    except Exception as e:
                        print(f"   ⚠️  Skipped row {row_num}: {input_data[:50] if input_data else 'Empty Input'} (Error: {str(e)[:50]}) ")
                        skipped += 1
                        # If an error occurred and features were already appended but labels weren't,
                        # pop the last feature to maintain synchronization.
                        if has_labels and len(all_features) > len(all_labels):
                            all_features.pop()
                        continue

                if not all_features:
                    print("\n❌ No features extracted!")
                    return None

                # Create DataFrame
                feature_names = self.get_feature_names()
                df = pd.DataFrame(all_features, columns=feature_names)

                # Add label column if available
                if has_labels and all_labels:
                    df['label'] = all_labels

                print(f"\n✅ Feature extraction complete!")
                print(f"   Total rows processed: {len(all_features)}")
                print(f"   Skipped: {skipped}")
                print(f"   Features extracted: {df.shape[1] - (1 if has_labels else 0)} (120 features)")

                # Save to CSV
                if output_file is None:
                    csv_filename = Path(csv_file_path).stem
                    output_file = f"{csv_filename}_features.csv"

                df.to_csv(output_file, index=False)
                print(f"\n💾 Saved features to: {output_file}")
                print(f"   Format: 120 feature columns + {'label column' if has_labels else 'no label'}")
                print(f"   Ready for Model 2 training!")

                print(f"\n{'='*95}\n")

                return df

        except FileNotFoundError:
            print(f"❌ Error: File not found: {csv_file_path}")
            return None
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            import traceback
            traceback.print_exc()
            return None


if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║   UNIVERSAL FEATURE EXTRACTOR                                                ║
    ║   Component 2: For Bidirectional Threat Intelligence Platform                ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝

    🎯 FEATURES:
    ✅ Extracts 120 numerical features from any input
    ✅ Single input extraction → numpy array
    ✅ Batch CSV processing → CSV with 120 features
    ✅ Smart detection: URL / Payload / JSON
    ✅ Fast: ~100ms per extraction

    📊 OUTPUT FORMATS FOR MODEL 2:

    1️⃣  SINGLE INPUT:
        numpy.array([120 features])
        → Use directly: model2.predict(features.reshape(1, -1))

    2️⃣  BATCH CSV:
        CSV file: feature_0, feature_1, ..., feature_119, label
        → Use for training: pd.read_csv('features.csv')

    🔗 INTEGRATION:
    Input → Feature Extractor → [120 features] → Model 2 → Prediction
    """)

    while True:
        print("\n" + "="*95)
        print("MAIN MENU")
        print("="*95)
        print("1. Extract features from single input")
        print("2. Batch extract from CSV file")
        print("3. Show feature names")
        print("0. Exit")
        print("="*95)

        choice = input("\nEnter choice: ").strip()

        if choice == '1':
            extractor = UniversalFeatureExtractor()
            test_input = input("\nEnter input (URL/Payload/JSON): ").strip()

            if test_input:
                features = extractor.extract_features(test_input)
                print(f"\n✅ Extracted {len(features)} features")
                print(f"   Shape: {features.shape}")
                print(f"   Data type: {features.dtype}")
                print(f"   Non-zero features: {np.count_nonzero(features)}")
                print(f"\n📊 Statistics:")
                print(f"   Min: {features.min():.3f}")
                print(f"   Max: {features.max():.3f}")
                print(f"   Mean: {features.mean():.3f}")
                print(f"   Std: {features.std():.3f}")

                # Show top 10 non-zero features
                feature_names = extractor.get_feature_names()
                non_zero_features = [(name, val) for name, val in zip(feature_names, features) if val != 0]

                if non_zero_features:
                    print(f"\n🔝 Top non-zero features:")
                    sorted_features = sorted(non_zero_features, key=lambda x: abs(x[1]), reverse=True)[:10]
                    for fname, fvalue in sorted_features:
                        print(f"   {fname:30s} = {fvalue:.4f}")

                print(f"\n💡 OUTPUT FORMAT FOR MODEL 2:")
                print(f"   Type: {type(features)}")
                print(f"   Shape: {features.shape}")
                print(f"   Usage: model2.predict(features.reshape(1, -1))")

        elif choice == '2':
            extractor = UniversalFeatureExtractor()

            print("\n💡 CSV Format:")
            print("   Required: 'input' or 'payload' or 'url' or 'data' column")
            print("   Optional: 'label' column")
            print("\n   Example:")
            print("   payload,label")
            print("   \"' OR 1=1--\",SQL_INJECTION")
            print("   <script>alert(1)</script>,XSS")

            csv_file = input("\n📂 Enter CSV file path: ").strip()
            if csv_file:
                output_file = input("💾 Output filename (press Enter for auto): ").strip()
                if not output_file:
                    output_file = None

                df = extractor.batch_extract_from_csv(csv_file, output_file)

                if df is not None:
                    print("\n📊 DataFrame Preview:")
                    print("="*95)
                    print(df.head())
                    print("="*95)
                    print(f"\nShape: {df.shape}")
                    print(f"Columns: {list(df.columns[:5])}... + {df.shape[1]-5} more")

        elif choice == '3':
            extractor = UniversalFeatureExtractor()
            feature_names = extractor.get_feature_names()

            print("\n" + "="*95)
            print("ALL 120 FEATURE NAMES")
            print("="*95 + "\n")

            print("📌 UNIVERSAL FEATURES [0-39]:")
            for i in range(40):
                print(f"   [{i:3d}] {feature_names[i]}")

            print("\n📌 URL FEATURES [40-79]:")
            for i in range(40, 80):
                print(f"   [{i:3d}] {feature_names[i]}")

            print("\n📌 PAYLOAD FEATURES [80-119]:")
            for i in range(80, 120):
                print(f"   [{i:3d}] {feature_names[i]}")

            print("\n" + "="*95)

        elif choice == '0':
            print("\n👋 Goodbye!")
            break

        else:
            print("\n❌ Invalid choice!")
            