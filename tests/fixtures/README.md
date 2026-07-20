# Fixtures

SAFE artifacts only. **Never commit live malware here.**

Real samples (from the SOC/CDC, MalwareBazaar, or GitHub sample sets) are
ingested at runtime from an external quarantine path and are never stored in
the repo. Tests synthesize a harmless `MZ`-prefixed file at runtime instead.
