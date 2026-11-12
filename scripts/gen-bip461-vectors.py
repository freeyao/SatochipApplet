#!/usr/bin/env python3
"""Generates src/test/resources/org/satochip/applet/bip461_sign_vectors.csv.

The expected signatures come from the BIP461 reference implementation, not from this
repository: pass the path of bips/bip-0461 (https://github.com/bitcoin/bips), which holds
reference.py and sign_test_vectors.csv.

    scripts/gen-bip461-vectors.py /path/to/bips/bip-0461 > src/test/resources/org/satochip/applet/bip461_sign_vectors.csv

The output is the valid official vectors, followed by 300 vectors drawn from a fixed seed (so
the file is reproducible), the first five of which are edge cases: seckey 1, seckey n-1,
msghash 0, msghash n-1 and msghash n+1.
"""
import csv
import os
import random
import sys

bip_dir = sys.argv[1]
sys.path.insert(0, bip_dir)
import reference as R  # noqa: E402

rows = []
with open(os.path.join(bip_dir, "sign_test_vectors.csv")) as f:
    for row in csv.DictReader(f):
        if row["sig"]:
            rows.append((row["seckey"], row["msghash"], row["sig"], "BIP461: " + row["comment"]))

rnd = random.Random(461)
for i in range(300):
    seckey = rnd.randrange(1, R.n).to_bytes(32, "big")
    msghash = rnd.randbytes(32)
    comment = "random %d" % i
    if i == 0:
        seckey, comment = (1).to_bytes(32, "big"), "seckey=1"
    if i == 1:
        seckey, comment = (R.n - 1).to_bytes(32, "big"), "seckey=n-1"
    if i == 2:
        msghash, comment = bytes(32), "msghash=0"
    if i == 3:
        msghash, comment = (R.n - 1).to_bytes(32, "big"), "msghash=n-1"
    if i == 4:
        msghash, comment = (R.n + 1).to_bytes(32, "big"), "msghash=n+1"
    r, s = R.deterministic_sign(seckey, msghash)
    rows.append((seckey.hex(), msghash.hex(), (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex(), comment))

print("seckey,msghash,sig,comment")
for row in rows:
    print(",".join(row))
