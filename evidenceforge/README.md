# Meridian Partners - EvidenceForge Home Org

## What's in here
- `organizations/meridian-partners/includes/environment.yaml` — the persistent org:
  31 users (23 HQ in Draper UT, 8 branch in St. George UT), 37 systems, mostly
  Windows with a small Linux DMZ/proxy footprint, full network topology
  (segments, Zeek sensors, IDS, firewall w/ NAT).
- `organizations/meridian-partners/includes/baseline.yaml` — reusable baseline
  activity settings (medium intensity/variation).
- `tier1-baseline/scenario.yaml` — Tier 1 scenario: 24h pure baseline, no
  attack. Learn what "normal" looks like in this org before hunting anything.
- `edr_pools_bugfix.patch` — fixes a real crash in EvidenceForge's RunMRU
  command generator (see below).

## Setup on your machine / VM

```bash
git clone https://github.com/Cisco-Talos/EvidenceForge.git
cd EvidenceForge
uv sync

# Drop these files into place
cp -r /path/to/meridian-partners-setup/organizations scenarios/
cp -r /path/to/meridian-partners-setup/tier1-baseline scenarios/

# Apply the bugfix (see below for why this is needed)
git apply /path/to/meridian-partners-setup/edr_pools_bugfix.patch

# Validate, then generate
uv run eforge validate scenarios/tier1-baseline/scenario.yaml
uv run eforge generate scenarios/tier1-baseline/scenario.yaml -o ./output
```

The full 24h+8h-warmup run generates a lot of data (a 2h smoke test alone
produced ~130 files / 31MB) — give it several minutes, don't expect it to
finish in seconds.

## The bug (worth reporting upstream)

`APP-HQ-01` runs `mssql` as a service. When EvidenceForge models SQL Server's
background activity, it uses the real Windows built-in virtual service account
`NT SERVICE\MSSQLSERVER`. In `edr_pools.py`, `_runmru_command()` substitutes
that account name into a regex **replacement** string without escaping it:

```python
command = re.sub(r"\{(user|username)\}", username, command_template)
```

Python's `re.sub` treats the replacement argument as a template where `\1`,
`\g<name>`, etc. are special sequences. Any account name containing a bare
backslash (`NT SERVICE\...`, `NT AUTHORITY\...`, or a `DOMAIN\user` account)
crashes with `error: bad escape \M at position 10` — "NT SERVICE" is exactly
10 characters before the backslash.

Fix: wrap the replacement in `re.escape()`:

```python
command = re.sub(r"\{(user|username)\}", re.escape(username), command_template)
```

This is a legitimate, reproducible bug in an MIT-licensed Cisco Talos repo —
worth filing as a GitHub issue with this repro (any scenario with a database
role + `mssql` service will hit it).

## Next steps
1. Generate the Tier 1 baseline, load it into Wazuh, spend time just reading
   normal traffic (no hunting yet).
2. Move to Tier 2 (single-vector attack) once baseline feels familiar.
3. File the upstream bug report.
