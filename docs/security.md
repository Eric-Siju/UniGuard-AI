# Security & Unidirectional Compliance Guarantees (docs/security.md)

UniGuard AI is engineered specifically to conform with high-assurance unidirectional security requirements for air-gapped critical infrastructure and defense systems.

---

## 1. Zero Active Network Interaction

### No Outbound Packet Transmission
- The system never generates outbound IP packets to the monitored network.
- No ARP requests, ping probes, or ICMP destination unreachables are emitted.
- In deployment, the network interface card (NIC) connected to the monitored link operates in receive-only mode (physical Tx wire severed).

### No Active Scanning or Endpoint Probing
- Standard NIDS solutions perform active banner grabbing, OS fingerprinting, and vulnerability scans upon detecting suspicious traffic.
- UniGuard AI operates strictly on passive telemetry:
  - 5-tuple IP header characteristics
  - Inter-arrival timing patterns
  - Observable Layer 4/Layer 7 metadata without active handshakes

### Zero Payload Decryption
- Encryption privacy is strictly maintained. The system does not perform Man-in-the-Middle (MitM) TLS proxying or private key decryption.
- Encrypted channels are evaluated using observable statistical markers:
  - TLS ClientHello SNI domain entropy
  - Cipher suite list lengths
  - Packet size sequence variance
  - Connection cadence and burst ratios

---

## 2. Application Hardening & Defensive Engineering

1. **Safe File Uploads:** Uploaded datasets and PCAPs are limited to 50MB and validated against strict extension whitelists (`.pcap`, `.pcapng`, `.cap`, `.csv`).
2. **Path Traversal Protection:** File destinations are resolved using `pathlib.Path.resolve()` against dedicated storage roots to prevent directory climbing attacks (`../../`).
3. **Zero Command Injection:** All packet parsing is handled in-process by Python and Scapy without invoking external shell binaries or unsanitized CLI strings.
4. **Air-Gapped Local Operation:** No reliance on external internet endpoints, cloud AI APIs, or remote databases.
5. **No Hardcoded Credentials:** System uses standard local SQLite storage without embedded cloud tokens or plaintext secrets.
