import sys, zipfile, io, re

if len(sys.argv) < 3:
    print("Usage: python3 remove_docx_restriction.py locked.docx unlocked.docx")
    sys.exit(1)

inp, outp = sys.argv[1], sys.argv[2]

# read all entries
with zipfile.ZipFile(inp, 'r') as zin:
    namelist = zin.namelist()
    # if settings.xml not present, just copy
    if 'word/settings.xml' not in namelist:
        print("word/settings.xml not found — nothing to change. Just copying file.")
        with zipfile.ZipFile(outp, 'w') as zout:
            for n in namelist:
                zout.writestr(n, zin.read(n))
        sys.exit(0)

    settings = zin.read('word/settings.xml').decode('utf-8', errors='ignore')

    # remove documentProtection element (self-closing or open/close)
    new_settings = re.sub(r'<w:documentProtection\b[^>]*\/>|<w:documentProtection\b[^>]*>.*?<\/w:documentProtection>', '', settings, flags=re.S)

    # write all back to new archive
    with zipfile.ZipFile(outp, 'w') as zout:
        for n in namelist:
            if n == 'word/settings.xml':
                zout.writestr(n, new_settings.encode('utf-8'))
            else:
                zout.writestr(n, zin.read(n))

print(f"Wrote {outp}. Backup your original before opening.")
