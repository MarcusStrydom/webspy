# webspy

## Install

From GitHub (replace `YOUR_USER`):

    pip install "git+https://github.com/YOUR_USER/webspy.git"
    pip install "git+https://github.com/YOUR_USER/webspy.git@v0.1.0"   # pinned release

Usage:

    webspy example.com --profile standard --json report.json
    webspy --list-probes
    python -c "from webspy import Passive; print(Passive().get_tls_info('example.com'))"

Detection data ships inside the package (`webspy/config/*.json`); point `WEBSPY_CONFIG_DIR` or
`--config` at your own copies to override it.

---

# webspy

A passive web reconnaissance and audit toolkit: one Python file plus JSON detection data. Point it at a domain and it answers questions an investigator or auditor actually asks:

- What is this site made of, and who hosts it?
- What is it leaking, and what is it missing?
- Which ad networks, trackers and third parties does it talk to, and which other sites share its IDs?
- How old is the domain, and what did it used to look like?

"Passive" means webspy only makes ordinary requests (GETs, an OPTIONS, DNS lookups, a TLS handshake, public registries such as RDAP, crt.sh and the Internet Archive). It never sends exploit payloads, fuzzes parameters or tries to log in. It does send traffic to the target, so see [Responsible use](#responsible-use).

## Install

```bash
pip install -r requirements.txt   # requests, dnspython, mmh3 (optional)
```

Python 3.9+. Copy `webspy.py` and the `config/` folder into your project.

## Quick start

### Command line

```bash
python webspy.py example.com                          # standard audit
python webspy.py example.com --profile full --json report.json --markdown report.md
python webspy.py example.com --probe get_ad_syndicates --probe get_identifiers
python webspy.py --list-probes
```

### Library

```python
from webspy import Passive

spy = Passive()                                   # defaults from config/*.json
ads = spy.get_ad_syndicates('example.com')
trackers = spy.get_trackers('example.com', endpoints=['/', '/login'])
tls = spy.get_tls_info('example.com')

report = spy.run_audit('example.com', profile='standard')
print(report['summary']['severity_counts'])
spy.save_report(report, 'report.json')
print(spy.report_to_markdown(report))
```

### Several configured instances

`Passive(*confs, **options)` builds a probe set from the config files plus any overrides you give it. Declare as many as you like:

```python
light = Passive(deep=False, browser=False, endpoints=['/'],
                exposure={'exposed_files': ['/.env', '/.git/config']})
acme = Passive({'trackers': {'+patterns': [
                   {'pattern': r'cdn\.acme\.io', 'name': 'Acme', 'category': 'analytics'}]}},
               'my_config/',              # a folder (or single <section>.json) of overrides
               domain='example.com', timeout=5)
strict = acme.clone(timeout=3)            # derive from an existing instance

light.get_exposed_files('example.com')
acme.get_trackers()                       # domain taken from Passive(domain=...)
```

Each argument is a layer applied over the defaults, in order: a **dict**, a **path** (folder of `<section>.json` files, or one file) or a **Config** object. Keyword arguments are one more dict layer. Inside a section a key replaces the default value; prefix it with `+` (`'+patterns'`) to append to a list or update a dict instead. Names that are not sections are settings: `domain`, `endpoints`, `browser`, `deep`, `max_scripts`, `timeout`, `cache_ttl`, `workers`, `user_agent`, `nameservers`. Unknown sections, keys and bad regexes raise immediately, naming the offender. Arguments passed to a probe always win over the instance defaults.

Every probe returns `{'domain', 'time', 'value', ...}`. Endpoint-based probes key `value` by path, and any failure is reported as an `error` field instead of raising.

## Audit profiles

| Profile | Purpose | Probes |
|---|---|---|
| `quick` | 10-second health check | security headers, TLS, server info, cookies, HTTP→HTTPS, email auth |
| `standard` | Default security audit | headers, CSP, cookies, CORS, TLS, caching, methods, email, DNS hardening, RDAP, CDN/WAF, forms, SRI, third parties, exposed files, error pages |
| `full` | Audit plus investigation | everything above plus trackers, ad syndicates, ads.txt, identifiers, JS secrets, API discovery, CT logs, subdomain takeover, IP/ASN intel, Wayback, favicon hash, DNS records |

`run_audit` runs the probes (3 in parallel by default), then `derive_findings` converts the raw output into severity-ranked findings (`critical`, `high`, `medium`, `low`, `info`).

## Probe catalogue

**Headers and transport**
`get_page_info` · `get_security` · `get_csp_policy` · `get_cors` · `get_server_info` · `get_cache_headers` · `get_allowed_methods` · `get_mime_handling` · `get_rate_limit_headers` · `get_status_map` · `get_server_redirects` · `get_http_redirect_check` · `get_http_versions` · `get_tls_info`

**Fingerprinting**
`get_tech_fingerprint` · `get_engine_detection` · `get_waf_detection` · `get_cdn_detection` · `get_favicon_hash` · `get_error_page_fingerprint` · `get_comments_metadata`

**Exposure and secrets**
`get_exposed_files` · `get_js_file_analysis` · `get_api_discovery` · `get_graphql_introspection` · `get_sitemap` · `get_robots_sitemap` · `get_sri_usage` · `get_forms`

**DNS, email and registration**
`get_dns` · `get_dns_hardening` (CAA, DNSSEC, NS diversity, wildcard) · `get_email_security` (SPF/DMARC/MTA-STS/BIMI) · `get_ip_intel` (rDNS, ASN) · `get_rdap` (registrar, age, expiry) · `get_cert_transparency` · `get_takeover_candidates` · `get_wayback`

**Third parties, ads and attribution**
`get_trackers` · `get_ad_syndicates` · `get_ads_txt` · `get_external_resources` · `get_identifiers`

Run `python webspy.py --list-probes` for one-line descriptions of each.

## How ad and tracker detection works

Static HTML is a poor witness for modern ad stacks, so detection combines several layers of evidence and reports how strong each is.

1. **Browser-like fetch.** Ad-heavy sites often block unfamiliar user agents. Content probes use a browser UA by default (`browser=False` restores the honest `webspy/x.y` UA).
2. **Normalisation.** `https:\/\/ads.example`, `\u002f` and HTML entities are decoded before matching, so URLs inside inline JSON still match.
3. **Structured asset parsing.** Every `script`, `iframe`, `img`, `link`, `a` and `form` URL is resolved against the final page URL, including lazy-load attributes (`data-src`, `srcset`).
4. **Deep scan.** Up to N linked scripts are fetched and scanned. Tag-manager containers (GTM, Adobe DTM, Tealium) go first, because they list the pixels and networks a site loads at runtime.
5. **CSP allow-lists.** Hosts named in `Content-Security-Policy` are weak but useful evidence on JavaScript-rendered pages.
6. **ads.txt.** `get_ads_txt` parses authorised sellers, which is direct evidence of who monetises the site.
7. **Heuristic fallback.** Unknown third-party hosts whose names look like ad or tracking infrastructure (`ads.`, `adserv`, `pop`, `rtb`, `syndicat…`) are listed as `heuristic_ad_hosts`, so long-tail networks surface instead of passing unnoticed.

Each vendor hit carries `confidence` (`high`: loaded via a script, iframe or image URL, found in a fetched JS file, or seen repeatedly; `medium`: single mention in the page; `low`: CSP only), the `sources` that produced it and sample matches.

Every result includes `diagnostics`: status code, whether the response looks like a bot challenge, how many scripts were scanned, and notes such as "page renders client-side". **An empty result with `blocked_suspected: true` means "could not see", not "clean".**

Vendor categories: `ad_pixel`, `ad_server`, `ad_exchange`, `ad_sync` (identity/cookie-sync), `native_ad`, `affiliate`, `ad_network_aggressive` (pop-unders, push, redirect networks), plus `analytics`, `tag_manager`, `session_replay`, `chat_support`, `ab_testing`, `error_monitoring`, `fingerprinting`, `consent_management` and `abuse` (cryptominers and known supply-chain-compromised hosts).

## Investigation workflows

**Link sites to the same operator.** `get_identifiers` extracts Google Analytics/GTM/AdSense publisher IDs, Meta/TikTok/Pinterest/LinkedIn pixel IDs, Hotjar/Clarity/Yandex IDs, Sentry DSNs, emails, social profiles and crypto addresses. Search those values across other sites or in your threat-intel tooling. A shared AdSense publisher ID or Matomo site is strong ownership evidence.

**Profile the infrastructure.** `get_ip_intel` (ASN, prefix, rDNS) plus `get_cdn_detection`, `get_waf_detection`, `get_cert_transparency` and `get_favicon_hash` (paste the Shodan hint into a search) map the hosting footprint.

**Establish history.** `get_rdap` gives registrar, creation date and domain age; `get_wayback` gives first and latest captures and the years the site was archived.

**Map the third-party surface.** `get_external_resources` lists every third-party host by resource type, flags mixed content and shows which domains the site links out to.

## Audit workflows

- Headers, cookies, CORS, caching and TLS: `get_security`, `get_csp_policy`, `get_cookies`, `get_cors`, `get_cache_headers`, `get_tls_info`.
- Email spoofing exposure: `get_email_security` checks SPF strictness and the 10-lookup limit, DMARC policy, MTA-STS and more.
- Leaks: `get_exposed_files` (content-validated and soft-404-aware, so a SPA that returns 200 for everything does not drown you in false positives), `get_js_file_analysis` (secrets are masked in output), source maps.
- Dangling infrastructure: `get_takeover_candidates` finds CNAMEs to non-existent or unclaimed third-party services among CT-discovered subdomains.
- Supply chain: `get_sri_usage` and the `abuse` tracker category.

## Extending

Detection data lives in JSON files under `config/`, not in the code. Add a vendor by appending an entry to `patterns` in `config/trackers.json` (or per instance with `'+patterns'`, above):

```json
{ "pattern": "ads\\.example-network\\.com|examplenet\\.js", "name": "Example Network", "category": "ad_exchange" }
```

Patterns are case-insensitive regexes matched against HTML, URLs, linked JS and CSP. Add new probes as `def get_*(self, domain=None, ...)` on `Passive` (start with `domain = self._dom(domain)`); they appear in `--list-probes` and can be added to `AUDIT_PROFILES`. Add finding rules in `derive_findings`.

| File | Contents |
|---|---|
| `settings.json` | defaults for every option (user agents, domain, endpoints, timeout, cache TTL, workers, deep scan, nameservers), confidence and severity ranking, multi-part public suffixes |
| `trackers.json` | tracker/ad vendor patterns, ad categories, known infrastructure hosts |
| `edge_vendors.json` | CDN/edge vendor headers and CNAME patterns |
| `cms_signatures.json` | CMS body signatures, JS library signatures |
| `engine_detection.json` | server, X-Powered-By, cookie and file-extension checks |
| `waf_detection.json` | WAF headers, cookies and block-page patterns |
| `error_pages.json` | error page fingerprints |
| `secrets.json` | secret/credential regexes |
| `exposure.json` | exposed-file and API-doc candidate paths |
| `http_checks.json` | security headers, risky methods, rate-limit headers, MIME magic bytes (hex) |
| `content_checks.json` | HTML comment flag patterns, sensitive-path keywords |
| `graphql.json` | GraphQL introspection query and endpoint list |
| `ads_txt.json` | ads.txt seller domain to vendor names |
| `identifiers.json` | tracking/pixel ID regexes, social hosts |
| `takeover.json` | subdomain-takeover service signatures |
| `validators.json` | content validators for exposed-file hits |
| `profiles.json` | audit profiles (name to probe list; add your own) |

The default config files are loaded once at import; overrides are compiled when an instance is created. Regexes are validated on load, so a typo fails immediately with the file and entry named. Set `WEBSPY_CONFIG_DIR` to use a different config directory.

## Configuration

| Setting | Option / argument | Default |
|---|---|---|
| Response cache TTL (seconds, `0` disables) | `cache_ttl` | `120` (cache is per instance; `clear_cache()`) |
| Deep script scan | `deep` | `True` |
| Scripts to fetch | `max_scripts` | `12` |
| Browser-like UA | `browser` | `True` |
| Request timeout (seconds) | `timeout` | `8` |
| Default paths for endpoint probes | `endpoints` | `['/']` |
| Audit parallelism | `workers` | `3` |

All of these live in `config/settings.json`, can be set per instance, and can be overridden per probe call (`spy.get_trackers(d, deep=False)`).

The cache means a full audit fetches each page once rather than once per probe.

## Limitations

- No JavaScript execution. Ads injected only at runtime by code the scan cannot see will be missed. Check `diagnostics.notes`.
- A site that blocks the request returns a challenge page; webspy flags this but cannot get past it.
- Vendor tables go stale. Treat `unclassified_third_party_hosts` and `heuristic_ad_hosts` as leads.
- RDAP coverage varies by TLD (some ccTLDs are not reachable via `rdap.org`). Wayback and crt.sh are third-party services and may rate-limit or time out.
- DKIM selector probing is best-effort; a missing selector does not prove DKIM is absent.
- `derive_findings` is a triage aid, not a substitute for manual review.

## Responsible use

Use webspy only on systems you own or are authorised to assess. Probes such as `get_exposed_files` (~45 requests), `get_api_discovery`, `get_takeover_candidates` and `get_js_file_analysis` generate noticeable traffic and may trigger WAF alerts. Respect rate limits and applicable law and terms of service. Secrets found by `get_js_file_analysis` are masked in output; handle and report them responsibly.

## Changelog

**0.3**
- `Passive` is now instantiated: `Passive()` uses the JSON config, `Passive(conf, ..., **options)` layers overrides, `clone()` derives instances. Class-level calls such as `Passive.get_trackers(d)` become `Passive().get_trackers(d)`.
- All detection data is read from `config/` (new files: `ads_txt`, `identifiers`, `takeover`, `validators`, `profiles`). Config entries added by the 0.3 migration are listed in the file `_comment` fields.
- Probes now use the extended config: engine `header_checks`, CMS meta-generator and header signatures, GraphQL endpoint list, TLS/cookie thresholds, info-disclosure headers.
- `get_error_page_fingerprint` reports `takeover_risk` and treats `misconfig`/`serious` labels as exposed debug output.

**0.2**
- Rewrote ad and tracker detection (layers above); `get_ad_syndicates` and `get_trackers` now report confidence, evidence and diagnostics.
- Fixed the unclassified-host list in `get_trackers` (it listed every script URL, including first-party ones).
- Vendor table expanded to exchanges, SSPs, ID-sync, native and affiliate networks; categories refined.
- Registrable-domain logic now understands multi-part suffixes such as `co.za` and `co.uk`.
- `get_exposed_files` and `get_api_discovery` are soft-404 aware; large files are no longer downloaded in full.
- New probes: `get_ads_txt`, `get_identifiers`, `get_external_resources`, `get_forms`, `get_email_security`, `get_dns_hardening`, `get_ip_intel`, `get_rdap`, `get_wayback`, `get_takeover_candidates`, `get_http_redirect_check`.
- New: audit profiles, `run_audit`, `derive_findings`, JSON/Markdown reports, CLI, response cache.
- Removed the `Active` stub class and all inline comments.