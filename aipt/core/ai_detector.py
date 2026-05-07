import numpy as np
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict
import hashlib
import logging
from datetime import datetime

from .config import AIDetectionConfig
from .models import Vulnerability, Severity, VulnType, Evidence
from .async_engine import ResponseContext


class FeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'status_code',
            'content_length',
            'response_time',
            'header_count',
            'has_server_header',
            'has_xframe_header',
            'has_csp_header',
            'has_hsts_header',
            'content_type_html',
            'content_type_json',
            'content_type_xml',
            'has_error_keywords',
            'has_sql_keywords',
            'has_xss_keywords',
            'has_path_keywords',
            'redirect_count',
            'cookie_count',
            'set_cookie_count',
        ]

    def extract(self, response: ResponseContext) -> np.ndarray:
        headers = response.headers
        text_lower = response.text.lower()

        features = [
            response.status_code / 600.0,
            min(response.content_length / 100000.0, 10.0),
            min(response.response_time / 10.0, 5.0),
            len(headers) / 50.0,
            1.0 if 'server' in headers else 0.0,
            1.0 if 'x-frame-options' in headers else 0.0,
            1.0 if 'content-security-policy' in headers else 0.0,
            1.0 if 'strict-transport-security' in headers else 0.0,
            1.0 if 'text/html' in headers.get('Content-Type', '') else 0.0,
            1.0 if 'application/json' in headers.get('Content-Type', '') else 0.0,
            1.0 if 'application/xml' in headers.get('Content-Type', '') else 0.0,
            1.0 if any(kw in text_lower for kw in ['error', 'exception', 'fatal', 'warning']) else 0.0,
            1.0 if any(kw in text_lower for kw in ['sql', 'mysql', 'postgresql', 'sqlite', 'oracle']) else 0.0,
            1.0 if any(kw in text_lower for kw in ['script', 'javascript', 'alert', 'onerror']) else 0.0,
            1.0 if any(kw in text_lower for kw in ['../', '..\\', '/etc/', 'c:\\']) else 0.0,
            len(response.history) / 10.0,
            len(response.cookies) / 10.0,
            len([h for h in headers if h.lower() == 'set-cookie']) / 5.0,
        ]

        return np.array(features).reshape(1, -1)


class MLAnomalyDetector:
    def __init__(self, config: AIDetectionConfig):
        self.config = config
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self.training_data: List[np.ndarray] = []
        self.baseline_responses: List[Dict[str, Any]] = []
        self.baseline_established = False
        self.response_clusters: Dict[str, List[ResponseContext]] = defaultdict(list)
        self.logger = logging.getLogger(__name__)
        self._init_model()

    def _init_model(self):
        if not self.config.enabled:
            return

        try:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(
                contamination=self.config.contamination,
                random_state=42,
                n_estimators=100,
                max_samples='auto',
            )
        except ImportError:
            self.logger.warning("scikit-learn not available, falling back to statistical detection")
            self.model = None

    def add_baseline_response(self, response: ResponseContext):
        features = self.feature_extractor.extract(response)
        self.training_data.append(features.flatten())
        self.baseline_responses.append({
            'status': response.status_code,
            'length': response.content_length,
            'time': response.response_time,
            'hash': response.content_hash,
            'url': response.url,
        })

        self.response_clusters[response.content_hash[:8]].append(response)

        if len(self.training_data) >= self.config.training_samples and not self.baseline_established:
            self._train_model()

    def _train_model(self):
        if not self.model or len(self.training_data) < self.config.training_samples:
            return

        try:
            X = np.array(self.training_data)
            self.model.fit(X)
            self.baseline_established = True
            self.logger.info(f"AI model trained on {len(self.training_data)} samples")
        except Exception as e:
            self.logger.error(f"Model training failed: {e}")

    def detect_anomaly(self, response: ResponseContext) -> Tuple[bool, float, str]:
        if not self.baseline_established:
            if len(self.training_data) < 10:
                return False, 0.0, "Insufficient baseline data"
            return self._statistical_detection(response)

        if self.model and self.config.model_type == "isolation_forest":
            return self._ml_detection(response)
        else:
            return self._statistical_detection(response)

    def _ml_detection(self, response: ResponseContext) -> Tuple[bool, float, str]:
        try:
            features = self.feature_extractor.extract(response)
            prediction = self.model.predict(features)[0]
            score = self.model.decision_function(features)[0]
            confidence = abs(score)

            is_anomaly = prediction == -1
            anomaly_score = min(confidence * 2, 1.0)

            reasons = []
            if response.status_code >= 500:
                reasons.append(f"Server error: {response.status_code}")
            if response.response_time > 5.0:
                reasons.append(f"Slow response: {response.response_time:.2f}s")
            if response.content_length == 0 and response.status_code == 200:
                reasons.append("Empty response with 200 status")

            reason = "; ".join(reasons) if reasons else "ML anomaly detected"
            return is_anomaly and anomaly_score > self.config.anomaly_threshold, anomaly_score, reason

        except Exception as e:
            self.logger.error(f"ML detection error: {e}")
            return self._statistical_detection(response)

    def _statistical_detection(self, response: ResponseContext) -> Tuple[bool, float, str]:
        if len(self.baseline_responses) < 10:
            return False, 0.0, "Insufficient baseline data"

        lengths = [r['length'] for r in self.baseline_responses]
        times = [r['time'] for r in self.baseline_responses]
        statuses = [r['status'] for r in self.baseline_responses]

        mean_length = np.mean(lengths)
        std_length = np.std(lengths) if len(lengths) > 1 else 0
        mean_time = np.mean(times)
        std_time = np.std(times) if len(times) > 1 else 0

        anomalies = []
        scores = []

        if std_length > 0:
            z_length = abs(response.content_length - mean_length) / std_length
            if z_length > 3:
                anomalies.append(f"Content length anomaly: {response.content_length} vs {mean_length:.0f}")
                scores.append(min(z_length / 10, 1.0))

        if std_time > 0:
            z_time = abs(response.response_time - mean_time) / std_time
            if z_time > 3:
                anomalies.append(f"Response time anomaly: {response.response_time:.2f}s vs {mean_time:.2f}s")
                scores.append(min(z_time / 10, 1.0))

        if response.status_code >= 500:
            anomalies.append(f"Server error: {response.status_code}")
            scores.append(0.9)
        elif response.status_code == 403 and statuses.count(200) > 5:
            anomalies.append("Access forbidden - potential authorization issue")
            scores.append(0.7)

        if response.content_length == 0 and response.status_code == 200:
            anomalies.append("Empty response with 200 status")
            scores.append(0.6)

        is_anomaly = len(anomalies) > 0
        confidence = max(scores) if scores else 0.0
        reason = "; ".join(anomalies) if anomalies else "Normal"

        return is_anomaly, confidence, reason

    def detect_response_cluster_anomaly(self, response: ResponseContext) -> Tuple[bool, str]:
        if not self.config.response_clustering:
            return False, ""

        hash_prefix = response.content_hash[:8]
        cluster = self.response_clusters.get(hash_prefix, [])

        if len(cluster) > 5:
            avg_time = np.mean([r.response_time for r in cluster])
            if abs(response.response_time - avg_time) > 3 * np.std([r.response_time for r in cluster]):
                return True, f"Response time deviation from cluster: {response.response_time:.2f}s vs avg {avg_time:.2f}s"

        return False, ""

    def behavioral_analysis(self, responses: List[ResponseContext]) -> List[Dict[str, Any]]:
        if not self.config.behavioral_analysis or len(responses) < 5:
            return []

        findings = []
        status_codes = [r.status_code for r in responses]
        response_times = [r.response_time for r in responses]
        content_lengths = [r.content_length for r in responses]

        status_distribution = defaultdict(int)
        for status in status_codes:
            status_distribution[status] += 1

        total = len(responses)
        for status, count in status_distribution.items():
            ratio = count / total
            if status >= 500 and ratio > 0.1:
                findings.append({
                    'type': 'High Server Error Rate',
                    'severity': 'HIGH',
                    'description': f'{ratio*100:.1f}% of responses returned {status} errors',
                    'confidence': min(ratio * 2, 1.0)
                })

        if response_times:
            avg_time = np.mean(response_times)
            slow_count = sum(1 for t in response_times if t > avg_time * 3)
            if slow_count / len(response_times) > 0.2:
                findings.append({
                    'type': 'Performance Degradation',
                    'severity': 'MEDIUM',
                    'description': f'{slow_count} unusually slow responses detected',
                    'confidence': min(slow_count / len(response_times), 1.0)
                })

        return findings


class ResponseDiffer:
    def __init__(self):
        self.baseline_responses: Dict[str, ResponseContext] = {}

    def set_baseline(self, url: str, response: ResponseContext):
        self.baseline_responses[url] = response

    def compare(self, url: str, current: ResponseContext) -> Optional[Dict[str, Any]]:
        baseline = self.baseline_responses.get(url)
        if not baseline:
            return None

        differences = {}

        if current.status_code != baseline.status_code:
            differences['status_change'] = {
                'from': baseline.status_code,
                'to': current.status_code
            }

        length_diff = abs(current.content_length - baseline.content_length)
        if length_diff > baseline.content_length * 0.1:
            differences['content_length_change'] = {
                'from': baseline.content_length,
                'to': current.content_length,
                'diff': length_diff
            }

        time_diff = abs(current.response_time - baseline.response_time)
        if time_diff > baseline.response_time * 2:
            differences['response_time_change'] = {
                'from': baseline.response_time,
                'to': current.response_time,
                'diff': time_diff
            }

        if differences:
            return {
                'url': url,
                'differences': differences,
                'severity': 'HIGH' if 'status_change' in differences else 'MEDIUM'
            }

        return None
