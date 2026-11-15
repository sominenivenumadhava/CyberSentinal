"""Environment and Dependency Verification Script for CyberSentinel."""
import os
import sys
from pathlib import Path
import importlib.metadata

# Configure writable cache directory for Matplotlib
mpl_cache = Path(__file__).parent / ".cache" / "matplotlib"
mpl_cache.mkdir(parents=True, exist_ok=True)
os.environ["MPLCONFIGDIR"] = str(mpl_cache.resolve())

import torch
import pandas as pd
import numpy as np
import sklearn
from pytorch_tabnet.tab_model import TabNetClassifier
import shap
import fastapi
import uvicorn
import matplotlib
import joblib
import multipart
import imblearn

def main():
    print("=" * 60)
    print("        CYBERSENTINEL ENVIRONMENT VERIFICATION")
    print("=" * 60)
    print(f"Python Runtime:     {sys.version.split()[0]}")
    print(f"PyTorch Version:    {torch.__version__} (CPU: {not torch.cuda.is_available()})")
    print(f"Pandas Version:     {pd.__version__}")
    print(f"NumPy Version:      {np.__version__}")
    print(f"Scikit-learn:       {sklearn.__version__}")
    print(f"PyTorch TabNet:     {importlib.metadata.version('pytorch-tabnet')} (TabNetClassifier ready)")
    print(f"SHAP Version:       {shap.__version__}")
    print(f"FastAPI Version:    {fastapi.__version__}")
    print(f"Uvicorn Version:    {uvicorn.__version__}")
    print(f"Matplotlib Version: {matplotlib.__version__}")
    print(f"Joblib Version:     {joblib.__version__}")
    print(f"Multipart Version:  {multipart.__version__}")
    print(f"Imbalanced-learn:   {imblearn.__version__}")
    
    # Test tensor compute
    a = torch.randn(10, 10)
    b = torch.matmul(a, a.t())
    assert b.shape == (10, 10), "Matrix multiplication shape error"
    print("\n[+] PyTorch CPU tensor compute verified: SUCCESS")
    print("[+] All 12 requested core dependencies successfully verified!\n")

if __name__ == "__main__":
    main()
