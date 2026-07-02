import json
import math
import logging
from typing import Dict, Any, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class StructuralMathGuard:
    def __init__(self, max_entropy: float = 5.5, max_depth: int = 5, min_compression_ratio: float = 1.1):
        """
        Initializes the Math Guard with statistical thresholds.
        max_entropy: Standard English text is around 3.5 - 4.5. Base64/Encrypted data is 6.0+.
        max_depth: How many levels deep a JSON graph is allowed to go.
        min_compression_ratio: Anomalous, densely packed malicious code fails to compress normally.
        """
        self.max_entropy = max_entropy
        self.max_depth = max_depth
        self.min_compression_ratio = min_compression_ratio
        self.metrics = {
            "payloads_analyzed": 0,
            "entropy_blocks": 0,
            "depth_blocks": 0,
            "compression_blocks": 0
        }

    def _calculate_shannon_entropy(self, data_string: str) -> float:
        """Calculates the Shannon Entropy (statistical randomness) of a string."""
        if not data_string:
            return 0.0

        entropy = 0.0
        length = len(data_string)
        char_counts = {}

        for char in data_string:
            char_counts[char] = char_counts.get(char, 0) + 1

        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_compression_ratio(self, data_string: str) -> float:
        """
        Approximates Kolmogorov Complexity.
        Measures how compressible the payload is using zlib.
        Natural JSON compresses well. Obfuscated/encrypted malware does not.
        """
        import zlib
        if not data_string or len(data_string) < 50:
            # Too short to meaningfully compress
            return 2.0

        original_bytes = data_string.encode('utf-8')
        compressed_bytes = zlib.compress(original_bytes)

        # Ratio = Original Size / Compressed Size
        return len(original_bytes) / len(compressed_bytes)

    def _calculate_graph_depth(self, node: Any, current_depth: int = 0) -> int:
        """Recursively calculates the maximum geometric depth of a JSON object."""
        if isinstance(node, dict):
            if not node:
                return current_depth + 1
            return max(self._calculate_graph_depth(v, current_depth + 1) for v in node.values())
        elif isinstance(node, list):
            if not node:
                return current_depth + 1
            return max(self._calculate_graph_depth(item, current_depth + 1) for item in node)
        else:
            return current_depth

    def inspect_payload(self, raw_payload: str) -> str:
        """Evaluates the payload mathematically. Returns a safe payload or a lockdown payload."""
        self.metrics["payloads_analyzed"] += 1

        try:
            # 1. Check Entropy first (Catches Base64 Multimodal Attacks instantly)
            entropy = self._calculate_shannon_entropy(raw_payload)
            if entropy > self.max_entropy:
                self.metrics["entropy_blocks"] += 1
                logger.warning(
                    f"MATH GUARD: High Entropy Detected ({entropy:.2f} > {self.max_entropy}). Possible obfuscation/Base64 attack.")
                return self._generate_lockdown("Information-Theoretic Anomaly: Entropy threshold exceeded.")

            # 2. Check Kolmogorov Compression Anomaly (Catches packed code/malware arrays)
            compression_ratio = self._calculate_compression_ratio(raw_payload)
            if compression_ratio < self.min_compression_ratio and len(raw_payload) > 100:
                self.metrics["compression_blocks"] += 1
                logger.warning(
                    f"MATH GUARD: Compression Anomaly Detected ({compression_ratio:.2f} < {self.min_compression_ratio}). Payload is uncompressible/obfuscated.")
                return self._generate_lockdown("Density Anomaly: Payload fails structural compressibility thresholds.")

            # 3. Check Geometric Depth (Catches Deep Nesting Attacks)
            parsed_json = json.loads(raw_payload)
            depth = self._calculate_graph_depth(parsed_json)

            if depth > self.max_depth:
                self.metrics["depth_blocks"] += 1
                logger.warning(
                    f"MATH GUARD: Geometric Anomaly Detected. Graph depth ({depth}) exceeds limit ({self.max_depth}).")
                return self._generate_lockdown("Geometric Anomaly: Graph nesting depth exceeded.")

            # If the math checks out, return the original payload untouched
            return raw_payload

        except json.JSONDecodeError:
            # If it's not JSON, we just rely on the entropy check we already did
            return raw_payload

    def _generate_lockdown(self, reason: str) -> str:
        return json.dumps({
            "security_alert": "CRITICAL",
            "layer": "Mathematical Structural Guard",
            "action_taken": "Payload Blocked",
            "reason": reason
        })

    def get_metrics_report(self) -> Dict[str, Any]:
        return self.metrics