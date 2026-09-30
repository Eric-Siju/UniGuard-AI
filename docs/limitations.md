# Operational Limitations & Future Work (docs/limitations.md)

While UniGuard AI delivers robust passive detection for unidirectional IP traffic, real-world deployment in operational technology (OT) enclaves presents inherent constraints.

---

## 1. Known Operational Limitations

### Lack of Bidirectional Handshake Confirmation
In unidirectional monitoring, reverse traffic (e.g. server SYN-ACK or HTTP 200 response) is discarded by design or absent from the monitored tap. Consequently:
- Successful TCP handshakes must be inferred from the arrival of subsequent PSH/ACK packets or forward sequence numbers.
- Half-open scanning attempts cannot be verified via server RST responses unless reverse streams are tapped separately.

### Obfuscated & Padded Encrypted Channels
Adversaries employing sophisticated traffic padding (e.g. Obfs4, Shadowsocks) or artificial jitter morphing can obscure packet size distributions. In such scenarios, single-flow detection confidence is reduced, necessitating multi-flow correlation over extended time windows.

### Synthetic Benchmark Representation
The included demonstration datasets are generated offline to safely simulate realistic cyber threats without attacking production infrastructure. While statistical distributions model real-world threats, performance in diverse enterprise networks requires calibration against site-specific baselines.

---

## 2. Recommended Future Enhancements

1. **FPGA / DPDK Hardware Acceleration:** Offload Scapy packet capture to Intel DPDK or FPGA NICs for sustained 10Gbps+ wire-speed unidirectional sniffing.
2. **Deep Packet Inter-Arrival Jitter Profiling (LSTM / Transformer):** Incorporate lightweight temporal sequence models (e.g. Tiny-Transformer) for advanced encrypted C2 beaconing detection.
3. **Dual-Diode Correlation:** Allow ingestion of two separate unidirectional streams (inbound diode + outbound diode) to perform full bidirectional state tracking without enabling return communication between isolated enclaves.
4. **Automated SIEM/Syslog Push:** Export standardized CEF / Syslog events over an isolated management VLAN to Splunk, QRadar, or Microsoft Sentinel.
