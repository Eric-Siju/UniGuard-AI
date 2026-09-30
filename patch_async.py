from pathlib import Path

# 1. Update streamer.py
streamer_path = Path("backend/app/engine/streamer.py")
s_code = streamer_path.read_text(encoding="utf-8")
old_loop = """        # Spawn async streaming worker in the running event loop
        loop = asyncio.get_event_loop()
        self.worker_task = loop.create_task(self._run_stream_worker())"""

new_loop = """        # Spawn async streaming worker in the running event loop
        try:
            loop = asyncio.get_running_loop()
            self.worker_task = loop.create_task(self._run_stream_worker())
        except RuntimeError:
            try:
                loop = asyncio.get_event_loop()
                self.worker_task = loop.create_task(self._run_stream_worker())
            except Exception as e:
                print(f"[!] Could not spawn async stream worker: {e}")"""

if old_loop in s_code:
    streamer_path.write_text(s_code.replace(old_loop, new_loop), encoding="utf-8")
    print("Updated streamer.py loop handling")

# 2. Update endpoints.py to async def
ep_path = Path("backend/app/api/endpoints.py")
ep_code = ep_path.read_text(encoding="utf-8")
ep_code = ep_code.replace("def start_demo_stream(", "async def start_demo_stream(")
ep_code = ep_code.replace("def pause_demo_stream(", "async def pause_demo_stream(")
ep_code = ep_code.replace("def resume_demo_stream(", "async def resume_demo_stream(")
ep_code = ep_code.replace("def stop_demo_stream(", "async def stop_demo_stream(")
ep_path.write_text(ep_code, encoding="utf-8")
print("Updated endpoints.py to async def")
