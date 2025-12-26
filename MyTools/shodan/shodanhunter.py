#!/usr/bin/env python3

import shodan
import argparse
import json
import sys

SHODAN_API_KEY = ""

def load_queries(file):
    try:
        with open(file, "r") as f:
            return [q.strip() for q in f if q.strip()]
    except:
        print("[!] Failed to read query file")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="ShodanHunter Enterprise Recon Tool"
    )

    parser.add_argument(
        "-qf", "--query-file",
        required=True,
        help="File containing Shodan queries"
    )

    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain / company"
    )

    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Output file"
    )

    args = parser.parse_args()

    api = shodan.Shodan(SHODAN_API_KEY)
    queries = load_queries(args.query_file)

    results = {}

    print(f"[+] Target: {args.domain}")
    print(f"[+] Queries Loaded: {len(queries)}\n")

    for q in queries:
        query = f"{q} {args.domain}"
        print(f"[>] Running: {query}")

        try:
            res = api.search(query)
            for h in res["matches"]:
                ip = h.get("ip_str")
                port = h.get("port")
                product = h.get("product")
                org = h.get("org")

                key = f"{ip}:{port}"
                results[key] = {
                    "ip": ip,
                    "port": port,
                    "product": product,
                    "org": org,
                }
        except shodan.APIError as e:
            print(f"[!] Shodan error: {e}")

    with open(args.output, "w") as f:
        for r in results.values():
            f.write(f"{r['ip']}:{r['port']} | {r['product']} | {r['org']}\n")

    print(f"\n[✓] Results saved to {args.output}")
    print(f"[✓] Total Targets: {len(results)}")

if __name__ == "__main__":
    main()
