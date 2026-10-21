import os
import sys

# 讓 `import main` 在 repo 根目錄外執行 pytest 時也能找到模組
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
