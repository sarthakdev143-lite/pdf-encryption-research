# Authentication matrix

- files: 32   engines: 6   probes: 1344
- **AUTH-BYPASS: 0**   FAIL-CONTROL: 0

## Summary by verdict

- ACCEPTED-CONTROL: 192
- ACCEPTED-OWNER: 192
- REJECTED: 960

> Note (2026-10-29, VPS): `corpus/writers/reportlab_s256.pdf` is absent from
> this run — `pyaes` is not installed in `.venv`, so reportlab refuses
> `strength=256` and `writers.py` skips it (10 writers, 32 files here vs 33
> on the original box). Hence FAIL-CONTROL is 0 here, not 3; the three
> F-2026-002 rows are unchanged and still reproducible from the frozen PoC
> `findings/poc/reportlab_s256_nonconforming.pdf`. See `findings/LOG.md`
> F-2026-002 and `findings/24-7.log`.
