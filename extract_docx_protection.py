#!/usr/bin/env python3
import sys, zipfile, xml.etree.ElementTree as ET

if len(sys.argv) < 2:
    print("Usage: python3 extract_docx_protection.py locked.docx")
    raise SystemExit(1)

fn = sys.argv[1]
with zipfile.ZipFile(fn, 'r') as z:
    try:
        s = z.read('word/settings.xml').decode('utf-8', errors='ignore')
    except KeyError:
        print("word/settings.xml not found in archive.")
        raise SystemExit(2)

# find the documentProtection element
try:
    root = ET.fromstring(s)
except Exception:
    # attempt to find xml fragment
    start = s.find("<?xml")
    root = ET.fromstring(s[start:]) if start>=0 else ET.fromstring(s)

# look for element (namespace-agnostic)
dp = None
for el in root.iter():
    if el.tag.lower().endswith('documentprotection'):
        dp = el
        break

if dp is None:
    print("No <w:documentProtection ...> element found.")
    print("Snippet of settings.xml:")
    print(s[:800])
    raise SystemExit(3)

attrs = dp.attrib
# print common attributes if present
print("Attributes found on w:documentProtection:")
for k,v in attrs.items():
    print(f"{k} = {v}")

# show the common names as plain keys too
def getkey(klist):
    for k in klist:
        if k in attrs:
            return attrs[k]
    return None

print("\nNormalized results (copy these):")
print("hash    :", getkey(['{http://schemas.openxmlformats.org/wordprocessingml/2006/main}hash','hash']))
print("salt    :", getkey(['{http://schemas.openxmlformats.org/wordprocessingml/2006/main}salt','salt']))
print("spinCnt :", getkey(['{http://schemas.openxmlformats.org/wordprocessingml/2006/main}cryptspincount','{http://schemas.openxmlformats.org/wordprocessingml/2006/main}cryptSpinCount','cryptSpinCount','cryptspincount']))
print("alg attrs (if any):")
for k in ('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}cryptProviderType','{http://schemas.openxmlformats.org/wordprocessingml/2006/main}cryptAlgorithmClass','{http://schemas.openxmlformats.org/wordprocessingml/2006/main}cryptAlgorithmType','{http://schemas.openxmlformats.org/wordprocessingml/2006/main}cryptAlgorithmSid'):
    if k in attrs:
        print(k, "=", attrs[k])
