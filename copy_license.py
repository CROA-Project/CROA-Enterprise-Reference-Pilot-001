import shutil
import os

shutil.copy2("../CROA/LICENSE", "LICENSE")
shutil.copy2("../CROA/LICENSE-CODE", "LICENSE-CODE")
shutil.copy2("../CROA/LICENSE-DOCS", "LICENSE-DOCS")

print("Licenses copied")
