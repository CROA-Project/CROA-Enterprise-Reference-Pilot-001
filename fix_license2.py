import os

with open("LICENSE", "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace('\ufffd', '\u2014')

with open("LICENSE", "w", encoding="utf-8") as f:
    f.write(text)

print("Replaced replacement character in LICENSE")
