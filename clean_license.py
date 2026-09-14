import os
import re

with open("LICENSE", "r", encoding="utf-8") as f:
    text = f.read()

# Replace any weird character before " Licensing" and before " Creative Commons"
text = text.replace('\ufffd', '')
text = text.replace('\u00e2\u20ac\u201d', '\u2014')
text = text.replace('\u00e2\u20ac\u201c', '\u2013')
text = text.replace('\u00e2\u20ac\u2122', '\u2019')
text = text.replace('\u00e2\u20ac\u0153', '\u201c')
text = text.replace('\u00e2\u20ac\u009d', '\u201d')
text = text.replace('\u00e2\u20ac', '\u2014')
text = text.replace('\u00c2', '')

with open("LICENSE", "w", encoding="utf-8") as f:
    f.write(text)

print("Cleaned up LICENSE mojibake")
