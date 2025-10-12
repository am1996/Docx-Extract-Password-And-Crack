#!/usr/bin/env python3
"""
ooxml_cracker.py
Multithreaded/multiprocess wordlist tester for OOXML DocumentProtection hashes.

USAGE:
  - Edit STORED_HASH_B64, SALT_B64, SPIN_COUNT and WORDLIST_PATH below.
  - Run: python ooxml_cracker.py
NOTE: This is CPU-bound. The script uses multiprocessing (ProcessPoolExecutor).
      Use only in authorized/ethical contexts (CTFs, HTB boxes you own/are allowed to test).
"""

import base64
import struct
import hashlib
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import multiprocessing

# ------------------ Configuration (EDIT these) ------------------
STORED_HASH_B64 = "UPwAdz5xBFZEs/SunE+qtLni6oTLXfdptNfqejwh0qnUvI4piX639KrpYxY72w9rmDOvS2z5C7A0qU4hvHcaAw=="
SALT_B64        = "blHFZKQKqMSpSZOISsjdHQ=="
SPIN_COUNT      = 100000
WORDLIST_PATH   = "wordlist.txt"     # one candidate password per line (no trailing newline stripping required)
CHUNK_SIZE      = 256                # number of passwords per worker task (tune this)
MAX_WORKERS     = None               # None -> defaults to cpu_count()
# ----------------------------------------------------------------

# internal decoded constants (don't modify)
_STORED_HASH = STORED_HASH_B64.strip()
_SALT = base64.b64decode(SALT_B64) if SALT_B64 else b""

def ooxml_hash_match_for_password(password: str, salt: bytes, spin_count: int, stored_hash_b64: str) -> bool:
    """
    Implements the OOXML DocumentProtection hashing/verifier for a single password.
    Returns True if password matches stored_hash_b64.
    """
    # prepare bytes: UTF-16LE password, prepend salt
    pwd_bytes = password.encode("utf-16-le")
    g = salt + pwd_bytes

    # iterate spin_count rounds
    for i in range(spin_count):
        h = hashlib.sha512(g).digest()
        g = h + struct.pack("<I", i)
    # drop last 4 bytes and base64 the rest
    result_b64 = base64.b64encode(g[:-4]).decode("ascii")
    return result_b64 == stored_hash_b64

def check_chunk(chunk_passwords):
    """
    Worker function: iterate chunk_passwords and return the matching password if found,
    otherwise return None.
    NOTE: This runs in a separate process.
    """
    for pw in chunk_passwords:
        if ooxml_hash_match_for_password(pw, _SALT, SPIN_COUNT, _STORED_HASH):
            return pw
    return None

def read_wordlist(path):
    p = Path(path)
    if not p.exists():
        print(f"Wordlist not found: {path}", file=sys.stderr)
        sys.exit(2)
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        # strip trailing newlines but keep inner spacing
        for line in f:
            pw = line.rstrip("\n\r")
            if pw:  # skip empty lines
                yield pw

def chunked(iterator, n):
    """Yield lists of size up to n from iterator."""
    chunk = []
    for item in iterator:
        chunk.append(item)
        if len(chunk) >= n:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

def main():
    word_iter = read_wordlist(WORDLIST_PATH)
    chunks = list(chunked(word_iter, CHUNK_SIZE))
    total_passwords = sum(len(c) for c in chunks)
    print(f"Loaded {total_passwords} candidate passwords in {len(chunks)} chunks (chunk size {CHUNK_SIZE}).")
    workers = MAX_WORKERS or multiprocessing.cpu_count()
    print(f"Starting ProcessPoolExecutor with {workers} workers. spin_count={SPIN_COUNT}. (This may be slow.)")

    found = None
    try:
        with ProcessPoolExecutor(max_workers=workers) as exe:
            # submit all chunks; we will iterate as they complete
            futures = {exe.submit(check_chunk, chunk): idx for idx, chunk in enumerate(chunks)}
            checked_chunks = 0
            for fut in as_completed(futures):
                checked_chunks += 1
                res = fut.result()
                if res:
                    found = res
                    print(f"\n*** MATCH FOUND: '{found}' ***")
                    # attempt to cancel remaining futures (best-effort)
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    break
                # optional progress info
                if checked_chunks % 10 == 0 or checked_chunks == len(futures):
                    print(f"Checked {checked_chunks}/{len(futures)} chunks...", end="\r", flush=True)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(1)

    if found:
        print(f"Password is: {found}")
    else:
        print("No match found in provided wordlist.")

if __name__ == "__main__":
    main()
