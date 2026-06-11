# StealthOps Roadmap

## Planned

### Defanged indicator support
Auto-refang indicators at all input boundaries (console REPL, CLI arg, web UI form).

Patterns to handle: `[.]`, `(.)`, `[:]`, `hxxp://`, `hxxps://`.

UX: silent normalization with a one-line notice (e.g. `→ Refanged: 127.0.0.1`) so investigators can confirm the tool understood the input correctly. Apply server-side in web UI and reflect cleaned value in the result header.

Implementation: single `refang(indicator)` utility + ~3-4 call sites.
