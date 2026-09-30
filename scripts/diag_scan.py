import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pandas as pd
from backend.app.engine.feature_extractor import extract_flow_features, network_context
from backend.app.engine.rules import RuleEngine
from backend.app.engine.ml_detector import ml_detector
from backend.app.engine.correlator import threat_correlator

network_context.reset()
df = pd.read_csv("data/sample/port_scan.csv")
rules = RuleEngine()

for i, row in df.head(25).iterrows():
    raw = row.to_dict()
    feats = extract_flow_features(raw, update_context=True)
    r = rules.evaluate_flow(raw, feats)
    ml = ml_detector.predict(feats)
    alt = threat_correlator.correlate(raw, feats, r, ml)
    alt_name = alt.threat_type if alt else "No alert"
    print(f"Flow {i}: unique_dst_ports={feats['unique_dst_ports']}, fan_out={feats['fan_out']}, rules={r}, ml={ml['prediction']} (conf={ml['confidence']:.2f}), alert={alt_name}")
