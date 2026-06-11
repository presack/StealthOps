# StealthOps Roadmap

## Planned

### Defanged indicator support
Auto-refang indicators at all input boundaries (console REPL, CLI arg, web UI form).

Patterns to handle: `[.]`, `(.)`, `[:]`, `hxxp://`, `hxxps://`.

UX: silent normalization with a one-line notice (e.g. `→ Refanged: 127.0.0.1`) so investigators can confirm the tool understood the input correctly. Apply server-side in web UI and reflect cleaned value in the result header.

Implementation: single `refang(indicator)` utility + ~3-4 call sites.

### New enrichment provider: AlienVault OTX
Free API, community-submitted pulse database covering IPs, domains, and URLs. Fills a threat intel gap not represented by any current provider. Target type: IP + domain.

### New enrichment provider: BGPView
Free, no API key required. Adds BGP peer/upstream/downstream graph and prefix announcements — genuine ASN depth that complements RIPEstat without overlap. Target type: ASN (extend existing ASN support).

### New enrichment provider: ipinfo.io
Clean ASN + org + geolocation in a single call for any IP. Fills the geo gap (no current provider returns a reliable city/country). Free tier available. Target type: IP.
