import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(sys.stdin.read(), encoding="utf-8")
print(f"Successfully wrote {p}")
