# Repository agent rules

## Oracle probes that compile but do not decode

When investigating a decoder gap with the Turbo Basic oracle, any probe that:

1. compiles successfully, and
2. fails during TBX scanning, decoding, lifting, or rendering

must be promoted to the local wild-probe corpus immediately. Copy the
compiled executable to `wild/hits/` using a unique, descriptive stem. The
`wild/hits/` directory is gitignored; these executables must never be
committed.

Record the probe's source shape, dialect, and exact first failure in `PLAN.md`
or the relevant investigation log. Keep the `.bas` probe in temporary working
storage unless it is later promoted to a redistributable fixture.

Compilation failure is not sufficient for promotion: leave rejected probes in
the temporary probe directory and record them only as negative evidence when
they materially narrow the investigation.

Promotion to `tests/fixtures/corpus/` still requires the normal calibration
rule: identify the construct, preserve fail-loud behavior for unknown shapes,
and verify the fixture's byte-exact round trip with the oracle.
