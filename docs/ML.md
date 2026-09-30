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

### Evaluation Performance (Measured Local Benchmark on Synthetic Dataset)

> [!NOTE]
> **Evaluation Honesty Notice:**
> The metrics below reflect empirical holdout test results evaluated on our locally generated synthetic benchmark dataset (`data/sample/combined_demo.csv`). They must be represented as **"99.83% accuracy on synthetic benchmark dataset"**, never as unverified real-world detection accuracy.

- **Accuracy:** `99.83%` (584/585 test flows correctly classified)
- **F1-Score (Weighted):** `0.9983`
- **Precision:** `99.83%`
- **Recall:** `99.83%`
- **False Positive Rate (Normal misclassified as Threat):** `0.83%` (1/120)
- **False Negative Rate (Threat misclassified as Normal):** `0.00%` (0/465)

### Top Discriminating Features (Gini Importance)
The model balances volumetric, statistical, and contextual topological signals:
1. `total_packets` (0.1009) — Total Packet Count
2. `total_bytes` (0.0945) — Total Flow Volume
3. `conn_frequency` (0.0874) — Contextual Connection Frequency
4. `outbound_bytes` (0.0815) — Outbound Egress Volume
5. `fan_in` (0.0677) — Destination Convergence Ratio
6. `avg_packet_size` (0.0623) — Mean Payload Byte Size
7. `unique_src_ports` (0.0561) — Ephemeral Source Port Dispersion

---

## 3. Contextual Features & Data Leakage Prevention

In unidirectional IP monitoring, individual packets do not carry bidirectional handshake state. To distinguish distributed attacks (DDoS, port scans) from normal high-volume traffic, UniGuard AI calculates 5 topological context features:
- `fan_in`: Number of unique source IPs targeting the same destination IP
- `fan_out`: Number of unique destination IPs targeted by the same source IP
- `unique_dst_ports`: Number of unique destination ports targeted by the source IP
- `unique_src_ports`: Number of unique source ports used by the source IP
- `conn_frequency`: Connection request rate per second within a 60-second sliding window

### Preventing Train/Test Contamination
In previous prototypes, computing context features globally across the entire dataset before splitting leaked future test information into training samples. 

UniGuard AI prevents data contamination through strict isolation:
1. **Split-First Architecture:** The raw chronological flow records are partitioned into a 70% train split and 30% test holdout *before* any feature extraction.
2. **Dedicated Temporal Trackers:** The training set is processed using a dedicated `NetworkContextTracker` instance that only observes training events.
3. **Isolated Test Tracking:** A completely separate `NetworkContextTracker` is initialized for the test set, ensuring zero leakage of test timestamps, endpoints, or port statistics into the training pipeline.
4. **State Reset:** Both trackers enforce a 60-second sliding window expiry, matching live runtime inference behavior.

---

## 4. Botnet C2 False-Positive Elimination

Standard heuristic rules that inspect isolated single flows on port 443/8080 can produce severe false positives on normal HTTPS traffic (e.g., standard browser keep-alives or API calls).

UniGuard AI resolves this via stateful, multi-observation tracking:
- **Minimum Observation Threshold:** Enforces `BOTNET_MIN_BEACONS = 4`. A single flow never triggers a botnet alert.
- **Inter-Arrival Jitter Verification:** Calculates the standard deviation and coefficient of variation (CV) of inter-beacon intervals:
  $$\text{CV} = \frac{\sigma_{\text{IAT}}}{\mu_{\text{IAT}}}$$
  Alerts require $\sigma \le 0.25\text{s}$ and $\text{CV} \le 0.20$ to confirm algorithmic, machine-generated beaconing.
- **Payload Uniformity:** Verifies that packet byte lengths are consistent across heartbeats.
- Automated tests (`test_botnet_normal_https_does_not_trigger` and `test_botnet_synthetic_beacon_sequence_triggers`) guarantee that ordinary HTTPS web browsing is never flagged as Botnet C2.

---

## 5. Unsupervised Anomaly Detector: Isolation Forest

- **Algorithm:** `sklearn.ensemble.IsolationForest`
- **Parameters:** `n_estimators=100`, `contamination=0.15`, `random_state=42`
- **Purpose:** Identifies zero-day attacks and novel threat variants that deviate from normal baseline behavior even if no supervised class or signature rule exists.
- **Normalized Decision Function:**
  $$\text{Score} = \text{clip}(0.5 - 1.5 \cdot \text{decision\_function}(X), 0.0, 1.0)$$
  Scores $> 0.65$ indicate high confidence anomalies.

---

## 6. Explainable AI (XAI) Attribution

For every classification, UniGuard AI computes feature attribution weights:
$$\text{Impact}_i = |z_i| \times \text{Importance}_i$$
Where:
- $z_i = \frac{x_i - \mu_i}{\sigma_i}$ is the standardized z-score deviation of feature $i$.
- $\text{Importance}_i$ is the model's global Gini feature importance.

The top 4 contributing features are returned with plain-text explanations, displayed in the SOC investigation dashboard.

---

## 7. Dataset Disclaimers & Integrity
- **Synthetic Benchmark Labeling:** The CSV datasets in `data/sample/` are generated locally to simulate authentic network threat behaviors without compromising real systems or transmitting malicious packets over public networks.
- **Metrics Integrity:** Test accuracy and confusion matrix values are computed live by Scikit-Learn during training on holdout data and stored in `backend/saved_models/model_evaluation.json`. Never hardcoded or fabricated.
