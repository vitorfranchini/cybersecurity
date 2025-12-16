import os
import hashlib
import requests
import time
import math
import json
from itertools import cycle

# --- CONFIGURATION ---
API_KEYS = [
    "API_KEY_1",
]
API_KEY = cycle(API_KEYS)
BASE_URL = "https://www.virustotal.com/api/v3"
EXTENSIONS_TARGET = [".mp4", ".o", ".wmv", ".rb", ".pdf.scr", ".xls", ".com", ".psd1", ".mst", ".tlb", ".msh2", ".7z", ".m3u8", ".asf", ".pdb", ".dump", ".doc", ".mp4.exe", ".bmp", ".doc.exe", ".psm1", ".out", ".jpg", ".ipa", ".vhd", ".ods", ".chm", ".hta", ".lnk", ".so", ".odt", ".xz", ".manifest", ".desktop", ".bas", ".ade", ".exe", ".ocx", ".json", ".iqy", ".sldm", ".ldb", ".patch", ".wbk", ".info", ".wsc", ".wsf", ".ini", ".mdb", ".webp", ".tmp", ".reg", ".bash", ".conf", ".php", ".xlm", ".yaml", ".lua", ".iss", ".au3", ".slk", ".ppsm", ".gz", ".groovy", ".csh", ".url", ".msc", ".psc2", ".msh1xml", ".mda", ".wps", ".bz2", ".pkg", ".bin", ".jsp", ".eml", ".jar", ".drv", ".xlsx", ".pl", ".xhtml", ".zip", ".a", ".docm.html", ".sct", ".mshxml", ".ost", ".aab", ".cpl", ".emf", ".png.install", ".swp", ".m3u", ".cs", ".sed", ".application", ".potm", ".img", ".docx", ".jnlp", ".mov", ".prg", ".docm", ".vbs", ".pdf", ".bak", ".old", ".run", ".dif", ".rom", ".xltm", ".xapk", ".mhtml", ".ahk", ".sys", ".cdxml", ".adp", ".pptm", ".rar", ".resources", ".appref-ms", ".efi.signed", ".bat", ".xla", ".msu", ".rtf", ".scr", ".tar", ".txt.exe", ".apk", ".dll", ".z", ".msp", ".sqlite3", ".awk", ".lzh", ".wmf", ".odp", ".yml", ".ico", ".ace", ".ppam", ".hlp", ".resx", ".pps", ".cdb", ".ppt", ".svg", ".xlw", ".efi", ".scf", ".xlsb", ".config", ".csproj", ".msh", ".py", ".aspx", ".wim", ".arj", ".inf", ".vba", ".png", ".msg", ".ws", ".xlsm", ".pdf.exe", ".cab", ".wsh", ".pst", ".pif", ".msi", ".gadget", ".xlam", ".jsc", ".sh", ".setup", ".vbe", ".cfg", ".xll", ".ko", ".rexa", ".mp3", ".png.exe", ".upd", ".class", ".sln", ".xlt", ".dmp", ".pol", ".csv", ".ress", ".pptx", ".iso", ".cmd", ".ksh", ".webloc.asset", ".nsi", ".jpeg", ".ps2xml", ".mkv", ".psc1", ".command", ".msh1", ".xml", ".elf", ".js", ".clixml", ".html", ".ppkg", ".ps1", ".xls.exe", ".wasm", ".lck", ".mdt", ".gif", ".vb", ".lock", ".mde", ".fish", ".jse", ".asp", ".fw", ".sqlite", ".avi", ".jpg.exe", ".dex", ".pyw", ".job", ".mht", ".dot", ".vhdx", ".msh2xml", ".wma", ".ps1xml", ".pot", ".mdf", ".zsh", ".dotm", ".ps2", ".mui", ".mdn", ".db", ".htm"]
REQUEST_INTERVAL = math.ceil(max(2, 16 / len(API_KEYS)))
LOG_FILE = "results.txt"
CACHE_FILE = "verified_files.txt"
# --------------------

if not API_KEYS or API_KEYS[0] == "API_KEY_1":
    print("Errorr: No API key configured.")
    exit()


malicious_paths = []  
pending_analyses = []  

def calculate_sha256(filepath):
      sha256_hash = hashlib.sha256()
      try:
            with open(filepath, "rb") as f:
                  for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
      except Exception as e:
            print(f"Error reading file {filepath}: {e}")
            return None

def get_headers():
      key = next(API_KEY)
      return {"x-apikey": key}

def log_result(message):
      print(message)
      with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(message + "\n")

def load_cache():
      if not os.path.exists(CACHE_FILE):
            return set()
      try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                  return set(line.strip() for line in f if line.strip())
      except Exception as e:
            print(f"Error loading cache: {e}")
            return set()
      
def save_to_cache(filepath):
      try:
            abs_path = os.path.abspath(filepath)
            with open(CACHE_FILE, "a", encoding="utf-8") as f:
                  f.write(abs_path + "\n")
      except Exception as e:
            print(f"Error saving to cache: {e}")

def check_file_hash(file_hash):
      url = f"{BASE_URL}/files/{file_hash}"
      response = requests.get(url, headers=get_headers())
      return response

def upload_file(filepath):
      SIZE_32 = 33554432 
      SIZE_650 = 681574400
    
      try:
            file_size = os.path.getsize(filepath)
            url = f"{BASE_URL}/files"

            if file_size >= SIZE_650:
                  msg = f"SKIPPED (TOO BIG > 650MB): {filepath}"
                  print(msg)
                  log_result(msg)
                  return None

            if file_size >= SIZE_32:
                  print(f"Big file ({file_size / (1024*1024):.2f} MB). Obtaining special utl...")
            
                  response_url = requests.get(f"{BASE_URL}/files/upload_url", headers=get_headers())
                  
                  if response_url.status_code == 200:
                        url = response_url.json().get('data')
                  else:
                        print(f"Getting big file url: {response_url.status_code}")
                        return response_url

            with open(filepath, 'rb') as f_stream:
                  files = {'file': (os.path.basename(filepath), f_stream)}
            
                  response = requests.post(url, headers=get_headers(), files=files)
                  return response

      except Exception as e:
            print(f"Error while uploading: {e}")
            return None

def check_analysis_status(analysis_id):
      url = f"{BASE_URL}/analyses/{analysis_id}"
      response = requests.get(url, headers=get_headers())
      return response

def parse_report(filepath, data):
      try:
            if not data or 'data' not in data:
                  return f"Invalid API response for {filepath}"
        
            attributes = data['data'].get('attributes', {})
            
            stats = attributes.get('last_analysis_stats') or attributes.get('stats')
        
            if not stats:
                  status = attributes.get('status', 'desconhecido')
                  return f"Statistics unavailable at the moment. VT Status: {status}"

            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            
            nome_arquivo = os.path.basename(filepath)
            status_str = f"[{nome_arquivo}] -> Maliciosos: {malicious} | Suspeitos: {suspicious} | Limpo: {undetected}"
        
            if malicious > 0:
                  malicious_paths.append(filepath)
                  return f"DANGER: {status_str}"
            else:
                  return f"CLEAN: {status_str}"

      except Exception as e:
            return f"Error while processing results: {str(e)}"

def scan_directory():
      found_files = []

      cached_files = load_cache()
      print(f"Loading cache... {len(cached_files)} files will be skipped.")

      print(f"Searching for possible malicious files (Checking {len(EXTENSIONS_TARGET)} different extentions)")

      abs_log = os.path.abspath(LOG_FILE)
      abs_cache = os.path.abspath(CACHE_FILE)
      abs_script = os.path.abspath(__file__)

      for root, dirs, files in os.walk("."):
            for file in files:
                  if any(file.lower().endswith(ext) for ext in EXTENSIONS_TARGET):
                        full_path = os.path.join(root, file)
                        abs_path = os.path.abspath(full_path)

                        if abs_path == abs_script:
                              print("Ignoring itself")
                              continue
                        if abs_path == abs_log:
                              print("Ignoring log")
                              continue
                        if abs_path == abs_cache:
                              print("Ignoring cache")
                              continue

                        if abs_path in cached_files:
                              continue

                        found_files.append(full_path)
      return found_files

# ------------------------------------------------------------

def main():
      files_to_check = scan_directory()
      total_files = len(files_to_check)
      
      print(f"\nFound {total_files} files.")
    
      if total_files == 0:
            return

      resp = input("Do you want to start the VirusTotal scan? (Y/n): ").strip().upper()
      if resp == '': resp = 'y'
      if resp.lower() != 'y':
            print("Cancelled by user.")
            return

      print(f"\nStarting scan. Interval of {REQUEST_INTERVAL}s between requests.\n")
      print(f"Using {len(API_KEYS)} API keys\n\n")

      for index, filepath in enumerate(files_to_check):
            
            print(f"Processing {index + 1}/{total_files}: {filepath}...")
            
            file_hash = calculate_sha256(filepath)
            if not file_hash:
                  continue

            response = check_file_hash(file_hash)

            if response.status_code == 200:
                  log_result(parse_report(filepath, response.json()))
                  save_to_cache(filepath)
      
            elif response.status_code == 404:
                  print(f"Unknown hash. Uploading file for analysis...")
                  up_resp = upload_file(filepath)

                  if up_resp and up_resp.status_code == 200:
                        analysis_id = up_resp.json()['data']['id']
                        pending_analyses.append((filepath, analysis_id))
                        print(f"File uploaded. Added to pending validation queue.")
                  else:
                        log_result(f"Upload failed for {filepath}. Status: {up_resp.status_code if up_resp else 'Error'}")
      
            elif response.status_code == 429:
                  print("Error 429: Quota exceeded")
                  return
            else:
                  log_result(f"API error for {filepath}: {response.content}")

            if index < total_files - 1:  
                  time.sleep(REQUEST_INTERVAL)
                        

      if pending_analyses:
            print("\n--- Checking results for pending uploads ---")
            print("Waiting 20 seconds for VirusTotal to process initial uploads...")
            time.sleep(20)

            for filepath, analysis_id in pending_analyses:
                  try:
                        max_retries = 10
                        for attempt in range(max_retries):
                              print(f"Querying analysis for {filepath} (Attempt {attempt+1})...")
                              res = check_analysis_status(analysis_id)

                              if res.status_code == 200:
                                    data = res.json()
                                    status = data['data']['attributes']['status']

                                    if status == 'completed':
                                          log_result(parse_report(filepath, data))
                                          break 
                                    else:
                                          print(f"Status: {status}. Waiting a little longer...")
                                          time.sleep(15)
                              else:
                                    print(f"Error checking analysis: {res.status_code}")
                                    break

                              time.sleep(REQUEST_INTERVAL)
                  except Exception as e:
                        print(f"Error while fetching queued files: {e}")


      print("\n" + "=" * 40)
      print("SCAN COMPLETE")
      print(f"Results saved to: {LOG_FILE}")
      print(f"Malicious files detected: {len(malicious_paths)}")

      if len(malicious_paths) > 0:
            print("\nFiles flagged as malicious:")
            for mp in malicious_paths:
                  print(f" - {mp}")

            del_resp = input("\nDO YOU WANT TO DELETE THESE MALICIOUS FILES? (TYPE 'DELETE' TO CONFIRM): ").strip()

            if del_resp == 'DELETE':
                  for mp in malicious_paths:
                        try:
                              os.remove(mp)
                              print(f"Deleted: {mp}")
                        except Exception as e:
                              print(f"Error deleting {mp}: {e}")
            else:
                  print("Files preserved.")
      else:
            print("No malicious files detected.")

if __name__ == "__main__":
      main()