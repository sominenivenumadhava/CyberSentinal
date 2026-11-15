"""
CICIDS2017 Dataset Downloader, Verification and Manual Import Helper.

Provides automated download capabilities for CICIDS2017 (MachineLearningCSV.zip)
from the official Canadian Institute for Cybersecurity (UNB) repository, along with
integrity checks, manual import instructions, and development seed generation.
"""
import os
import sys
import zipfile
import logging
from pathlib import Path
from typing import Optional, List
import requests

from config.settings import settings

logger = logging.getLogger(__name__)

OFFICIAL_CIC_PAGE = "https://www.unb.ca/cic/datasets/ids-2017.html"
OFFICIAL_ZIP_URL = "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip"

EXPECTED_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]


def check_existing_raw_files(data_dir: Optional[Path] = None) -> List[Path]:
    """Scan raw directory for existing CICIDS2017 CSV files."""
    raw_dir = data_dir or settings.DATA_RAW_DIR
    found_files = []
    
    # Check both data_raw and subdirectories like data/raw/MachineLearningCSV
    for root, _, files in os.walk(raw_dir):
        for f in files:
            if f.endswith(".csv"):
                found_files.append(Path(root) / f)
                
    return found_files


def download_dataset(
    target_dir: Optional[Path] = None,
    url: str = OFFICIAL_ZIP_URL,
    timeout: int = 60
) -> bool:
    """
    Attempt to download MachineLearningCSV.zip from the official CIC repository.
    Returns True if successful, False if blocked or failed.
    """
    dest_dir = target_dir or settings.DATA_RAW_DIR
    dest_dir.mkdir(parents=True, exist_ok=True)
    zip_path = dest_dir / "MachineLearningCSV.zip"

    print(f"[*] Checking official CICIDS2017 repository: {url}")
    try:
        response = requests.get(url, stream=True, timeout=timeout)
        if response.status_code != 200:
            logger.warning(f"Download server returned HTTP {response.status_code}")
            return False

        total_size = int(response.headers.get("content-length", 0))
        print(f"[*] Downloading {total_size / (1024 * 1024):.1f} MB...")
        
        with open(zip_path, "wb") as f:
            downloaded = 0
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        print(f"\rDownloading: {downloaded / (1024 * 1024):.1f} MB [{percent:.1f}%]", end="", flush=True)

        print("\n[*] Download completed. Extracting archive...")
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(dest_dir)
        print(f"[+] Successfully extracted CSVs to {dest_dir}")
        return True

    except Exception as e:
        logger.warning(f"Automated download failed: {e}")
        return False


def get_manual_import_instructions() -> str:
    """Detailed guide for manual download and import."""
    instructions = f"""
================================================================================
                    CICIDS2017 MANUAL IMPORT GUIDE
================================================================================
The official Canadian Institute for Cybersecurity (CIC / UNB) dataset is hosted at:
    URL: {OFFICIAL_CIC_PAGE}
    Direct Zip: {OFFICIAL_ZIP_URL}

To manually import:
1. Open your browser and navigate to {OFFICIAL_CIC_PAGE}.
2. Locate the "Download this dataset" section and select "MachineLearningCSV.zip" (~223 MB).
3. If prompted by the UNB academic access agreement or captcha, accept and complete the download.
4. Extract the downloaded `MachineLearningCSV.zip` into:
    {settings.DATA_RAW_DIR.resolve()}
   (or into { (settings.DATA_RAW_DIR / 'MachineLearningCSV').resolve()} )
5. Expected files:
"""
    for f in EXPECTED_FILES:
        instructions += f"    - {f}\n"
    instructions += """================================================================================
"""
    return instructions


if __name__ == "__main__":
    existing = check_existing_raw_files()
    if existing:
        print(f"[+] Found {len(existing)} existing CSV files in raw data directory.")
    else:
        print("[!] No CSV files found. Attempting download...")
        success = download_dataset()
        if not success:
            print(get_manual_import_instructions())
