import sys, zipfile, base64, xml.etree.ElementTree as ET

if len(sys.argv) < 2:
    print("Usage: python3 extract_office_ooxml_info.py file.docx")
    sys.exit(1)

fn = sys.argv[1]
z = zipfile.ZipFile(fn, 'r')
candidates = ["EncryptionInfo", "encryption.xml", "EncryptedPackage"]

if not any(name in z.namelist() for name in candidates):
    print("No EncryptionInfo/encryption.xml found in archive. It may be OLE/compound or a different format.")
    print("Archive list:", z.namelist()[:40])
    sys.exit(2)

# try to open EncryptionInfo or encryption.xml
xmldata = None
for name in ["EncryptionInfo", "encryption.xml"]:
    if name in z.namelist():
        xmldata = z.read(name)
        break

if xmldata is None:
    print("Could not find an XML encryption info file. It may be an OLE-packaged encrypted OOXML file.")
    sys.exit(3)

# try parse as XML
try:
    root = ET.fromstring(xmldata)
except Exception as e:
    # try to find XML inside binary blob
    s = xmldata.decode('utf-8', errors='ignore')
    start = s.find("<?xml")
    if start != -1:
        s2 = s[start:]
        try:
            root = ET.fromstring(s2)
        except Exception as e2:
            print("Could not parse encryption XML:", e2)
            sys.exit(4)
    else:
        print("EncryptionInfo XML not parseable.")
        sys.exit(5)

# find typical tags
def find_text(tag):
    el = root.find('.//{*}'+tag) or root.find('.//'+tag)
    return el.text if el is not None else None

salt = find_text('saltValue') or find_text('salt')
spin = find_text('spinCount')
verifier = find_text('encryptedVerifier') or find_text('verifier')
verifierHash = find_text('encryptedVerifierHash') or find_text('verifierHash')

print("Found fields (base64 or numbers). Copy these three base64 blobs (salt, verifier, verifierHash) below if present.")
print("spinCount:", spin if spin else "(not found)")

if salt:
    print("salt (base64):", salt)
else:
    print("salt: NOT FOUND")

if verifier:
    print("verifier (base64):", verifier)
else:
    print("verifier: NOT FOUND")

if verifierHash:
    print("verifierHash (base64):", verifierHash)
else:
    print("verifierHash: NOT FOUND")
