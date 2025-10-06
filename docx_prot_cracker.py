#!/usr/bin/env python3
"""
docx_prot_cracker.py

Usage:
  # verify single candidate
  python3 docx_prot_cracker.py verify <salt_b64> <hash_b64> <spinCount> <candidate_password>

  # run a wordlist (stops on first match)
  python3 docx_prot_cracker.py wordlist <salt_b64> <hash_b64> <spinCount> <wordlist.txt>

Notes:
- This tests two iteration conventions:
    Mode A: digest = SHA1(salt + pw_utf16le); then do for i in range(spinCount-1): digest = SHA1(digest)
    Mode B: digest = SHA1(salt + pw_utf16le); then do for i in range(spinCount): digest = SHA1(digest)
- It prints hex of computed digest and indicates which mode matched (if any).
- Uses only Python stdlib. Runs reasonably fast per candidate (SHA1 loops 100k times are moderately slow).
"""
import sys, base64, hashlib, time

def compute_digest(salt_bytes, password, spin, mode):
    """
    mode = 'A' -> iterate spin-1 times after initial SHA1(salt+pw)
    mode = 'B' -> iterate spin times after initial SHA1(salt+pw)
    """
    pw_bytes = password.encode('utf-16le')
    h = hashlib.sha1()
    h.update(salt_bytes + pw_bytes)
    digest = h.digest()
    # choose iteration count
    iters = spin-1 if mode == 'A' else spin
    # protect against negative iter
    if iters > 0:
        for _ in range(iters):
            digest = hashlib.sha1(digest).digest()
    return digest

def verify_one(salt_b64, hash_b64, spin, candidate):
    try:
        salt = base64.b64decode(salt_b64)
        target = base64.b64decode(hash_b64)
    except Exception as e:
        print("Error decoding base64 inputs:", e)
        return False

    for mode in ('A','B'):
        t0 = time.time()
        digest = compute_digest(salt, candidate, spin, mode)
        dt = time.time()-t0
        ok = digest == target
        print(f"Mode {mode}: computed {digest.hex()}  (time {dt:.2f}s) -> {'MATCH' if ok else 'no match'}")
        if ok:
            return True, mode, digest.hex()
    return False, None, None

def run_wordlist(salt_b64, hash_b64, spin, wordlist_path):
    try:
        salt = base64.b64decode(salt_b64)
        target = base64.b64decode(hash_b64)
    except Exception as e:
        print("Error decoding base64 inputs:", e)
        return

    total = 0
    tstart = time.time()
    with open(wordlist_path, 'rb') as f:
        for line in f:
            total += 1
            pw = line.rstrip(b'\r\n').decode('utf-8', errors='ignore')
            for mode in ('A','B'):
                digest = compute_digest(salt, pw, spin, mode)
                if digest == target:
                    elapsed = time.time()-tstart
                    print(f"\nFOUND! password='{pw}'  mode={mode}  attempts={total}  elapsed={elapsed:.2f}s")
                    print(f"computed digest (hex): {digest.hex()}")
                    return pw, mode
            if (total % 100) == 0:
                # status update
                elapsed = time.time()-tstart
                print(f"tried {total} passwords, elapsed {elapsed:.1f}s", end='\r')
    print("\nDone - no match found in wordlist.")
    return None, None

def main():
    if len(sys.argv) < 6:
        print(__doc__)
        return
    cmd = sys.argv[1].lower()
    salt_b64 = sys.argv[2]
    hash_b64 = sys.argv[3]
    try:
        spin = int(sys.argv[4])
    except:
        print("spinCount must be an integer.")
        return

    if cmd == 'verify':
        candidate = sys.argv[5]
        ok, mode, digest_hex = verify_one(salt_b64, hash_b64, spin, candidate)
        if ok:
            print(f"\nPassword OK -> '{candidate}' (mode {mode})")
        else:
            print("\nPassword did NOT match.")
    elif cmd == 'wordlist':
        wordlist = sys.argv[5]
        run_wordlist(salt_b64, hash_b64, spin, wordlist)
    else:
        print("Unknown command. Use 'verify' or 'wordlist'.")

if __name__ == '__main__':
    main()
