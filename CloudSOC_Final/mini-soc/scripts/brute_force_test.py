#!/usr/bin/env python3
"""Controlled brute-force simulation against YOUR OWN deployment.

Measures the real numbers needed for the Evaluation section:
  - attempts accepted before the IP is blocked
  - time from first attempt to first 403 (detection + block time)
  - requests rejected after the block (403) and by the rate limiter (429)

Usage:
  python scripts/brute_force_test.py --url http://<ALB-DNS>/login --attempts 30
Only run this against a server you own.
"""
import argparse
import json
import time

import requests


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True, help="Honeypot login URL, e.g. http://host/login")
    p.add_argument("--attempts", type=int, default=30)
    p.add_argument("--delay", type=float, default=0.0, help="Seconds between attempts")
    p.add_argument("--out", default="brute_force_result.json")
    args = p.parse_args()

    session = requests.Session()
    codes = {}
    first_block_at = None
    attempts_before_block = None
    t0 = time.perf_counter()
    latencies = []

    for i in range(1, args.attempts + 1):
        start = time.perf_counter()
        r = session.post(args.url, data={"username": "admin", "password": f"Pass{i}!"},
                         timeout=15, allow_redirects=False)
        latencies.append((time.perf_counter() - start) * 1000)
        codes[r.status_code] = codes.get(r.status_code, 0) + 1
        if r.status_code in (403, 429) and first_block_at is None:
            first_block_at = time.perf_counter() - t0
            attempts_before_block = i - 1
        print(f"attempt {i:>3}: HTTP {r.status_code}")
        time.sleep(args.delay)

    total = time.perf_counter() - t0
    result = {
        "target": args.url,
        "attempts_sent": args.attempts,
        "attempts_accepted_before_block": attempts_before_block,
        "seconds_to_first_block": round(first_block_at, 3) if first_block_at else None,
        "status_code_counts": codes,
        "avg_response_ms": round(sum(latencies) / len(latencies), 1),
        "total_seconds": round(total, 2),
    }
    print("\n" + json.dumps(result, indent=2))
    with open(args.out, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"\nSaved to {args.out}")


if __name__ == "__main__":
    main()
