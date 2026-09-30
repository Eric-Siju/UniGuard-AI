from pathlib import Path

# 1. Update schemas.py
schemas_path = Path("backend/app/models/schemas.py")
content = schemas_path.read_text(encoding="utf-8")
old_req = """class StreamControlRequest(BaseModel):
    action: str  # start, pause, resume, stop
    speed: Optional[float] = 1.0
    scenario: Optional[str] = "combined_demo" """

# Use line by line or search
lines = content.splitlines()
new_lines = []
for line in lines:
    if "action: str  # start, pause" in line:
        new_lines.append("    action: Optional[str] = 'start'  # start, pause, resume, stop")
        new_lines.append("    speed: Optional[float] = 1.0")
        new_lines.append("    scenario: Optional[str] = 'combined_demo'")
        new_lines.append("    dataset: Optional[str] = None")
        new_lines.append("    speed_factor: Optional[float] = None")
    elif "speed: Optional[float] = 1.0" in line and len(new_lines) > 0 and "speed_factor" in new_lines[-1]:
        continue
    elif "scenario: Optional[str]" in line and len(new_lines) > 0 and "speed_factor" in new_lines[-1]:
        continue
    else:
        new_lines.append(line)

schemas_path.write_text("\n".join(new_lines), encoding="utf-8")
print("Successfully patched schemas.py")

# 2. Update endpoints.py
ep_path = Path("backend/app/api/endpoints.py")
ep_content = ep_path.read_text(encoding="utf-8")
ep_lines = ep_content.splitlines()
out_ep = []
in_start = False
for line in ep_lines:
    if "@router.post(\"/api/demo/start\")" in line:
        in_start = True
        out_ep.append(line)
        out_ep.append("def start_demo_stream(req: Optional[StreamControlRequest] = None):")
        out_ep.append("    \"\"\"Starts real-time demo streaming pipeline.\"\"\"")
        out_ep.append("    scenario = 'combined_demo'")
        out_ep.append("    speed = 1.0")
        out_ep.append("    if req:")
        out_ep.append("        scenario = req.scenario or req.dataset or 'combined_demo'")
        out_ep.append("        speed = req.speed or req.speed_factor or 1.0")
        out_ep.append("    if scenario.endswith('.csv'):")
        out_ep.append("        scenario = scenario[:-4]")
        out_ep.append("    stream_engine.start_demo(scenario=scenario, speed=speed)")
        out_ep.append("    return {")
        out_ep.append("        'status': 'started',")
        out_ep.append("        'state': stream_engine.state,")
        out_ep.append("        'scenario': stream_engine.current_scenario,")
        out_ep.append("        'speed': stream_engine.speed")
        out_ep.append("    }")
    elif in_start:
        if line.startswith("@router.post(\"/api/demo/pause\")"):
            in_start = False
            out_ep.append(line)
    else:
        out_ep.append(line)

ep_path.write_text("\n".join(out_ep), encoding="utf-8")
print("Successfully patched endpoints.py")
