# Machine Learning & Threat Detection Models (docs/ML.md)

UniGuard AI implements a hybrid detection pipeline combining supervised ensemble classification, unsupervised outlier anomaly detection, and transparent Explainable AI (XAI).

## 1. Feature Representation Space (26 Dimensions)

| Feature Name | Type | Description | Primary Discriminator For |
|---|---|---|---|
| `duration` | Float | Total active flow lifespan (seconds) | Port Scan (low) vs Exfiltration (high) |
| `total_bytes` | Integer | Total bytes observed | Exfiltration vs Botnet heartbeats |
| `total_packets` | Integer | Total packet count | DDoS Floods vs Scan probes |
| `packets_per_sec` | Float | Flow packet velocity | DDoS volumetric surges |
| `bytes_per_sec` | Float | Bandwidth velocity (B/s) | Volumetric floods & Exfiltration |
| `avg_packet_size` | Float | Mean observed packet payload size | Botnet beacons (small) vs Exfil (large) |
| `packet_size_std` | Float | Variance of packet payload lengths | Encrypted streaming vs Fixed beacons |
| `iat_mean` | Float | Mean inter-arrival time between packets | Periodic C2 intervals |
| `iat_std` | Float | Inter-arrival jitter / standard deviation | Botnet periodicity detection |
| `iat_min` | Float | Minimum observed packet gap | Rapid flood bursts |
| `iat_max` | Float | Maximum observed packet gap | Idle timeouts |
| `fan_in` | Float | Unique sources targeting same destination | DDoS target convergence |
| `fan_out` | Float | Unique destinations contacted by source | Horizontal scanning sweeps |
| `unique_dst_ports`| Float | Unique ports probed by source host | Vertical port scans |
| `unique_src_ports`| Float | Ephemeral source ports observed | Botnet source port cycling |
| `conn_frequency` | Float | Connection requests per unit time | Reconnaissance velocity |
| `syn_count` | Float | Total TCP SYN flags observed | SYN floods & Half-open scans |
| `ack_count` | Float | Total TCP ACK flags observed | Established vs Uncompleted handshakes |
| `rst_count` | Float | Total TCP RST flags observed | Port reset responses |
| `syn_ratio` | Float | Ratio of SYN flags to total flags | Half-open scan & SYN flood verification |
| `dns_query_length`| Float | Length of domain string in chars | DNS Tunneling chunk size |
| `dns_entropy` | Float | Shannon entropy of domain string | DGA & Base64/Hex encoding |
| `dns_digit_ratio` | Float | Ratio of digits to string length | Hexadecimal exfiltration payloads |
| `dns_subdomain_depth`| Float| Number of dot-separated subdomain labels| Data chunk nesting |
| `outbound_bytes` | Float | Observed egress volume | Data Exfiltration |
| `outbound_ratio` | Float | Ratio of outbound to inbound volume | Asymmetric unidirectional exfiltration |

---

## 2. Supervised Classifier: Random Forest

- **Algorithm:** `sklearn.ensemble.RandomForestClassifier`
- **Parameters:** `n_estimators=100`, `max_depth=12`, `min_samples_split=4`, `random_state=42`
- **Target Classes (7):**
  1. `Normal`
  2. `DDoS`
  3. `Port Scan`
  4. `Botnet C2`
  5. `DGA / DNS Tunneling`
  6. `Suspicious Encrypted Traffic`
  7. `Data Exfiltration`

### Evaluation Performance (Measured on Test Holdout)
- **Accuracy:** `99.83%`
- **F1-Score (Weighted):** `0.9983`
- **Precision:** `99.83%`
- **Recall:** `99.83%`
- **False Positive Rate (Normal misclassified as Threat):** `< 0.2%`
- **False Negative Rate (Threat misclassified as Normal):** `< 0.2%`

---

## 3. Unsupervised Anomaly Detector: Isolation Forest

- **Algorithm:** `sklearn.ensemble.IsolationForest`
- **Parameters:** `n_estimators=100`, `contamination=0.15`, `random_state=42`
- **Purpose:** Identifies zero-day attacks and novel threat variants that deviate from normal baseline behavior even if no supervised class or signature rule exists.
- **Normalized Decision Function:**
  $$\text{Score} = \text{clip}(0.5 - 1.5 \cdot \text{decision\_function}(X), 0.0, 1.0)$$
  Scores $> 0.65$ indicate high confidence anomalies.

---

## 4. Explainable AI (XAI) Attribution

For every classification, UniGuard AI computes feature attribution weights:
$$\text{Impact}_i = |z_i| \times \text{Importance}_i$$
Where:
- $z_i = \frac{x_i - \mu_i}{\sigma_i}$ is the standardized z-score deviation of feature $i$.
- $\text{Importance}_i$ is the model's global Gini feature importance.

The top 4 contributing features are returned with plain-text explanations, displayed in the SOC investigation dashboard.

---

## 5. Dataset Disclaimers & Integrity
- **Synthetic Demo Data:** The CSV datasets in `data/sample/` are generated locally to simulate authentic network threat behaviors without compromising real systems or transmitting malicious packets over public networks.
- **Metrics Integrity:** Test accuracy and confusion matrix values are computed live by Scikit-Learn during training on holdout data and stored in `backend/saved_models/model_evaluation.json`.
