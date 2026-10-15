import os
import time
import urllib.request

URL = "https://files.pythonhosted.org/packages/22/e2/bc9603e2595363030a1c0687c347c164a8d0e8a54a9dcf79c3d8b9dfb1fe/tensorflow-2.22.0rc0-cp314-cp314-win_amd64.whl"
FILENAME = "tensorflow-2.22.0rc0-cp314-cp314-win_amd64.whl"
TOTAL_SIZE = 384083347

def download_with_resume():
    current_size = os.path.getsize(FILENAME) if os.path.exists(FILENAME) else 0
    if current_size >= TOTAL_SIZE:
        print(f"File {FILENAME} is already fully downloaded ({current_size:,} bytes).")
        return

    print(f"Starting/Resuming download of TensorFlow ({TOTAL_SIZE / (1024*1024):.1f} MB)...")
    
    while current_size < TOTAL_SIZE:
        try:
            req = urllib.request.Request(URL)
            req.add_header('User-Agent', 'Mozilla/5.0')
            if current_size > 0:
                req.add_header('Range', f'bytes={current_size}-')
            
            with urllib.request.urlopen(req, timeout=30) as resp, open(FILENAME, 'ab') as f:
                while True:
                    chunk = resp.read(1024 * 512)
                    if not chunk:
                        break
                    f.write(chunk)
                    current_size += len(chunk)
                    pct = (current_size / TOTAL_SIZE) * 100
                    print(f"\rProgress: {current_size / (1024*1024):.1f} / {TOTAL_SIZE / (1024*1024):.1f} MB ({pct:.1f}%)", end="", flush=True)
        except Exception as e:
            print(f"\nConnection paused ({e}). Reconnecting in 3 seconds to resume...")
            time.sleep(3)
            current_size = os.path.getsize(FILENAME) if os.path.exists(FILENAME) else 0

    print("\nDownload complete successfully!")

if __name__ == "__main__":
    download_with_resume()
