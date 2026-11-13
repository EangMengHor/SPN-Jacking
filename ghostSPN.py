#!/usr/bin/env python3
"""Read-only constrained-delegation SPN audit for Active Directory.

Compares msDS-AllowedToDelegateTo references with registered servicePrincipalName
attributes. A missing registration is a *candidate*, not proof of exploitability.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import ssl
import sys
from collections import defaultdict
from pathlib import Path


def values(obj: dict, key: str) -> list[str]:
    """Retrieve list-like LDAP fields regardless of capitalization."""
    raw = next((v for k, v in obj.items() if k.casefold() == key.casefold()), [])
    if raw is None:
        return []
    if not isinstance(raw, (list, tuple)):
        raw = [raw]
    return [str(v) for v in raw if v is not None]


def first(obj: dict, key: str) -> str:
    vs = values(obj, key)
    return vs[0] if vs else ""


def norm_spn(spn: str) -> str:
    return spn.strip().casefold()


def spn_host(spn: str) -> str:
    # SERVICE/host[:port][/name] -- not a complete SPN parser; cases requiring
    # special principal semantics should be manually reviewed.
    if "/" not in spn:
        return ""
    after = spn.split("/", 1)[1]
    host = after.split("/", 1)[0].split("@", 1)[0]
    if host.startswith("[") and "]" in host:  # bracketed IPv6 case
        host = host[1:host.index("]")]
    else:
        host = host.split(":", 1)[0]
    return host.rstrip(".").casefold()


def inventory(delegators: list[dict], registrations: list[dict], computers: list[dict], only: str | None, all_results: bool) -> list[dict]:
    spn_owners: dict[str, set[str]] = defaultdict(set)
    for obj in registrations:
        owner = first(obj, "sAMAccountName") or first(obj, "distinguishedName") or "<unnamed>"
        for spn in values(obj, "servicePrincipalName"):
            spn_owners[norm_spn(spn)].add(owner)

    host_names: set[str] = set()
    short_names: set[str] = set()
    for obj in computers:
        for name in (first(obj, "dNSHostName"), first(obj, "sAMAccountName").rstrip("$"), first(obj, "name")):
            if not name:
                continue
            canonical = name.rstrip(".").casefold()
            host_names.add(canonical)
            short_names.add(canonical.split(".", 1)[0])

    results: list[dict] = []
    for obj in delegators:
        name = first(obj, "sAMAccountName") or first(obj, "distinguishedName") or "<unnamed>"
        if only and name.casefold() != only.casefold():
            continue
        for spn in values(obj, "msDS-AllowedToDelegateTo"):
            owners = sorted(spn_owners.get(norm_spn(spn), set()))
            hostname = spn_host(spn)
            if owners:
                status = "REGISTERED"
                explanation = "Exact SPN is registered on an account"
            elif not hostname:
                status = "REVIEW_FORMAT"
                explanation = "Could not extract hostname from SPN"
            elif hostname in host_names:
                status = "UNREGISTERED_HOST_PRESENT"
                explanation = "Exact SPN missing; hostname matches an AD computer"
            elif hostname.split(".", 1)[0] in short_names:
                status = "UNREGISTERED_NAME_MISMATCH"
                explanation = "Exact SPN missing; short hostname matches an AD computer (check FQDN/alias)"
            else:
                status = "UNREGISTERED_HOST_ABSENT"
                explanation = "Exact SPN missing; no matching computer hostname in collected AD objects"
            if all_results or status != "REGISTERED":
                results.append({
                    "delegator": name,
                    "spn": spn,
                    "target_host": hostname,
                    "status": status,
                    "registered_owners": owners,
                    "reason": explanation,
                })
    return sorted(results, key=lambda row: (row["delegator"].casefold(), row["spn"].casefold()))


def collect_ldap(args: argparse.Namespace) -> tuple[list[dict], list[dict], list[dict]]:
    try:
        from ldap3 import Connection, NTLM, SIMPLE, Server, Tls
    except ImportError as exc:
        raise RuntimeError("ldap3 not installed; run: python3 -m pip install ldap3") from exc

    password = args.password or os.getenv("GHOSTSPN_PASSWORD") or getpass.getpass("AD password: ")
    if not password:
        raise RuntimeError("No password provided")
    if args.simple:
        login = args.username if ("@" in args.username or "\\" in args.username) else f"{args.username}@{args.domain}"
        auth = SIMPLE
    else:
        login = args.username if "\\" in args.username else f"{args.domain.split('.')[0].upper()}\\{args.username}"
        auth = NTLM
    tls = Tls(validate=ssl.CERT_NONE if args.insecure else ssl.CERT_REQUIRED)
    server = Server(args.dc_ip, port=args.port or (636 if args.ldaps else 389), use_ssl=args.ldaps, tls=tls, connect_timeout=args.timeout)
    con = Connection(server, user=login, password=password, authentication=auth, auto_bind=True, receive_timeout=args.timeout, auto_referrals=False)
    base = args.base_dn or ",".join(f"DC={component}" for component in args.domain.split("."))

    def fetch(ldap_filter: str, attributes: list[str]) -> list[dict]:
        out = []
        for msg in con.extend.standard.paged_search(search_base=base, search_filter=ldap_filter, attributes=attributes, paged_size=500, generator=True):
            if msg.get("type") == "searchResEntry":
                obj = dict(msg["attributes"])
                obj["distinguishedName"] = msg["dn"]
                out.append(obj)
        return out

    try:
        delegators = fetch("(msDS-AllowedToDelegateTo=*)", ["sAMAccountName", "msDS-AllowedToDelegateTo"])
        registrations = fetch("(servicePrincipalName=*)", ["sAMAccountName", "servicePrincipalName"])
        computers = fetch("(objectCategory=computer)", ["sAMAccountName", "dNSHostName", "name"])
        return delegators, registrations, computers
    finally:
        con.unbind()


def main() -> int:
    parser = argparse.ArgumentParser(description="Find unregistered SPNs referenced by Kerberos constrained delegation (READ-ONLY).")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("-orphaned", "--orphaned", action="store_true", help="Show unregistered SPNs (default)")
    grp.add_argument("--all", action="store_true", help="Include registered SPNs")
    parser.add_argument("--domain", "-d", help="AD DNS domain, e.g. lab.local")
    parser.add_argument("--dc-ip", help="Domain controller IP or DNS name")
    parser.add_argument("--username", "-u", help="AD username")
    parser.add_argument("--password", "-p", help="AD password (prefer prompt or GHOSTSPN_PASSWORD env var)")
    parser.add_argument("--simple", action="store_true", help="Use simple bind with UPN instead of NTLM bind")
    parser.add_argument("--ldaps", action="store_true", help="Use LDAPS instead of LDAP")
    parser.add_argument("--insecure", action="store_true", help="Skip LDAPS certificate checks (lab only)")
    parser.add_argument("--port", type=int, help="Override LDAP port")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--base-dn", help="Override LDAP search base")
    parser.add_argument("--delegator", help="Limit to a single delegation source, e.g. SRV01$")
    parser.add_argument("--json", "--output-json", dest="json_output", help="Save results to JSON file")
    parser.add_argument("--from-json", type=Path, help="Use offline JSON inventory instead of querying LDAP")
    args = parser.parse_args()

    try:
        if args.from_json:
            dataset = json.loads(args.from_json.read_text(encoding="utf-8"))
            delegators = dataset["delegators"]
            registrations = dataset["registrations"]
            computers = dataset["computers"]
        else:
            missing = [arg for arg in ("domain", "dc_ip", "username") if not getattr(args, arg)]
            if missing:
                parser.error("required for LDAP mode: " + ", ".join("--" + arg.replace("_", "-") for arg in missing))
            delegators, registrations, computers = collect_ldap(args)
        rows = inventory(delegators, registrations, computers, only=args.delegator, all_results=args.all)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"[!] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[!] LDAP error: {exc}", file=sys.stderr)
        return 1

    print(f"[+] Read-only scan: {len(delegators)} delegator objects, {len(registrations)} SPN owners, {len(computers)} computers")
    print(f"[+] Displaying {len(rows)} {'total' if args.all else 'unregistered/review'} delegation references\n")
    for row in rows:
        print(f"[{row['status']}] {row['delegator']:<20} {row['spn']}")
        if row["registered_owners"]:
            print(f"   Owners: {', '.join(row['registered_owners'])}")
        print(f"   {row['reason']}")
    if args.json_output:
        Path(args.json_output).write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
        print(f"\n[+] Saved: {args.json_output}")
    print("\n[!] Unregistered SPN != confirmed exploitability; review HOST aliases, FQDNs and delegation settings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
