"""webspy - web reconnaissance and audit toolkit.

Detection data lives in JSON files under ``webspy/config/`` (packaged with the library) (override the location with the
WEBSPY_CONFIG_DIR environment variable). ``Passive`` instances start from those
defaults and can be customised per instance:

    from webspy import Passive

    Passive().get_tls_info('example.com')                      # all defaults
    quiet = Passive(browser=False, deep=False, endpoints=['/', '/login'])
    mine = Passive({'trackers': {'+patterns': [{'pattern': r'cdn\\.acme\\.io', 'name': 'Acme', 'category': 'analytics'}]}},
                   'path/to/config_dir', timeout=5, domain='example.com')
    mine.get_trackers()

Most probes are passive (they only read what a normal visitor, DNS resolver or public
database would see). A few are *active* because there's no passive substitute for the
information they return:

  * ``get_port_scan``            opens TCP connections to the host to see what else is
                                  listening next to the web server (databases, admin
                                  panels, RDP/VNC, etc). This is a standard full TCP
                                  connect scan, not a raw/half-open SYN scan — connect
                                  scanning needs no elevated privileges, works the same
                                  on every OS, and finds exactly the same open ports a
                                  SYN scan would. If you specifically need a half-open
                                  scan (e.g. for its lower logging footprint across a
                                  very large port range), pair webspy with a dedicated
                                  scanner such as nmap -sS, run with appropriate
                                  privileges and authorization.
  * ``get_subdomain_bruteforce`` resolves a wordlist of common subdomain labels, to
                                  find names that were never issued a certificate and
                                  so never showed up in Certificate Transparency logs.
  * ``get_open_directory_listing`` requests a handful of common directory paths to see
                                  if the web server has autoindexing turned on.
  * ``get_whois``                 queries the WHOIS protocol directly (IANA referral
                                  chain), as a fallback for TLDs with no RDAP service.

Only run the active probes (``get_port_scan`` in particular) against hosts you own or
are otherwise authorized to test — unauthorized port scanning can violate laws such as
the US CFAA or the UK Computer Misuse Act and many providers' acceptable-use policies.
None of this is included in the ``quick`` profile by default; add the probe names to a
profile in your ``profiles.json`` (or pass them explicitly via ``probes=``) to opt in.
"""

__version__ = '0.1.0'

import base64
import concurrent.futures
import copy
import datetime
import hashlib
import html
import http.cookies
import inspect
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import dns.exception
import dns.resolver
import dns.reversename
import requests

__all__ = ['Passive', 'Config', 'AUDIT_PROFILES', 'main']


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_DIR = Path(os.environ.get('WEBSPY_CONFIG_DIR') or Path(__file__).resolve().parent / 'config')

SECTIONS = (
    'settings', 'trackers', 'edge_vendors', 'cms_signatures', 'engine_detection',
    'waf_detection', 'error_pages', 'secrets', 'exposure', 'http_checks',
    'content_checks', 'graphql', 'ads_txt', 'identifiers', 'takeover',
    'validators', 'profiles',
)
FREEFORM_SECTIONS = {'profiles'}          # keys are user-defined names, not a fixed schema
OPTION_ALIASES = {'user_agent': 'default_user_agent'}


def _ns(data):
    return SimpleNamespace(**{k: v for k, v in data.items() if not k.startswith('_')})


def _rx(pattern, flags, where):
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(f'{where}: invalid regex {pattern!r}: {exc}') from None


def _compile_settings(d, name):
    return {k: v for k, v in d.items() if not k.startswith('_')}


def _compile_trackers(d, name):
    vendors = [(_rx(p['pattern'], re.I, f'{name}.json patterns[{i}]'), p['name'], p['category'])
               for i, p in enumerate(d['patterns'])]
    return SimpleNamespace(
        vendors=vendors,
        ad_categories=set(d['ad_categories']),
        known_infra=_rx(d['known_infra_hosts'], re.I, f'{name}.json known_infra_hosts'),
        ad_like_host=_rx(d['ad_like_hosts'], re.I, f'{name}.json ad_like_hosts'),
    )


def _compile_edge_vendors(d, name):
    return SimpleNamespace(
        headers=[(h['header'].lower(), h['vendor']) for h in d['headers']],
        cnames=[(_rx(h['pattern'], re.I, f'{name}.json cname_patterns[{i}]'), h['vendor'])
                for i, h in enumerate(d['cname_patterns'])],
        server_checks=[(h['needle'].lower(), h['vendor']) for h in d['server_checks']],
        cert_issuer_checks=[(h['needle'].lower(), h['vendor']) for h in d['cert_issuer_checks']],
    )


def _compile_cms(d, name):
    def named(key):
        return [(_rx(h['pattern'], re.I, f'{name}.json {key}[{i}]'), h['name']) for i, h in enumerate(d[key])]
    return SimpleNamespace(
        body=named('cms_body'),
        js_libraries=named('js_libraries'),
        meta_generator=named('cms_meta_generator'),
        headers=[(h['header'].lower(), _rx(h['pattern'], re.I, f'{name}.json cms_headers[{i}]'), h['name'])
                 for i, h in enumerate(d['cms_headers'])],
    )


def _compile_engine(d, name):
    def needles(key):
        return [(h['needle'].lower(), h['engine'], h['confidence']) for h in d[key]]

    def regexes(key):
        return [(_rx(h['pattern'], re.I, f'{name}.json {key}[{i}]'), h['engine'], h['confidence'])
                for i, h in enumerate(d[key])]
    return SimpleNamespace(
        server_checks=needles('server_checks'),
        powered_by_checks=needles('powered_by_checks'),
        cookie_checks=regexes('cookie_checks'),
        extension_checks=regexes('extension_checks'),
        header_checks=[(h['header'].lower(), _rx(h['pattern'], re.I, f'{name}.json header_checks[{i}]'),
                        h['engine'], h['confidence']) for i, h in enumerate(d['header_checks'])],
    )


def _compile_waf(d, name):
    return SimpleNamespace(
        only_headers=[(h['header'].lower(), h['vendor'], h['confidence']) for h in d['waf_only_headers']],
        cookie_checks=[(h['pattern'].lower(), h['vendor']) for h in d['cookie_checks']],
        block_pages=[(_rx(h['pattern'], re.I, f'{name}.json block_page_checks[{i}]'), h['vendor'])
                     for i, h in enumerate(d['block_page_checks'])],
        server_checks=[(h['needle'].lower(), h['vendor']) for h in d['server_checks']],
    )


def _compile_error_pages(d, name):
    return SimpleNamespace(fingerprints=[
        (_rx(h['pattern'], re.I, f'{name}.json fingerprints[{i}]'), h['label'])
        for i, h in enumerate(d['fingerprints'])])


def _compile_secrets(d, name):
    return SimpleNamespace(patterns=[
        (_rx(h['pattern'], 0, f'{name}.json patterns[{i}]'), h['label'])
        for i, h in enumerate(d['patterns'])])


def _compile_http(d, name):
    ns = _ns(d)
    ns.mime_signatures = [(bytes.fromhex(h['hex']), h['mime']) for h in d['mime_signatures']]
    return ns


def _compile_content(d, name):
    return SimpleNamespace(
        comment_flags=[(_rx(h['pattern'], 0, f'{name}.json comment_flags[{i}]'), h['description'])
                       for i, h in enumerate(d['comment_flags'])],
        sensitive_cache_keywords=list(d['sensitive_cache_keywords']),
    )


def _compile_identifiers(d, name):
    return SimpleNamespace(
        patterns={k: _rx(v, 0, f'{name}.json patterns[{k}]') for k, v in d['patterns'].items()},
        social_hosts=tuple(d['social_hosts']),
    )


def _compile_takeover(d, name):
    return SimpleNamespace(signatures=[
        (_rx(h['pattern'], re.I, f'{name}.json signatures[{i}]'), h['service'],
         _rx(h['fingerprint'], 0, f'{name}.json signatures[{i}].fingerprint') if h.get('fingerprint') else None)
        for i, h in enumerate(d['signatures'])])


def _compile_validators(d, name):
    by_path = {}
    for i, v in enumerate(d['validators']):
        flags = (re.I if 'i' in v.get('flags', '') else 0) | (re.M if 'm' in v.get('flags', '') else 0)
        rx = _rx(v['pattern'], flags, f'{name}.json validators[{i}]')
        for path in v['paths']:
            by_path[path] = rx
    return SimpleNamespace(by_path=by_path)


def _compile_profiles(d, name):
    return SimpleNamespace(profiles={k: list(v) for k, v in d.items() if not k.startswith('_')})


_COMPILERS = {
    'settings': _compile_settings, 'trackers': _compile_trackers,
    'edge_vendors': _compile_edge_vendors, 'cms_signatures': _compile_cms,
    'engine_detection': _compile_engine, 'waf_detection': _compile_waf,
    'error_pages': _compile_error_pages, 'secrets': _compile_secrets,
    'http_checks': _compile_http, 'content_checks': _compile_content,
    'identifiers': _compile_identifiers, 'takeover': _compile_takeover,
    'validators': _compile_validators, 'profiles': _compile_profiles,
}


def _read_json(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f'{path}: not valid JSON ({exc})') from None


def _read_path(path):
    """A config directory (any <section>.json files in it) or a single <section>.json file."""
    path = Path(path)
    if path.is_dir():
        found = {p.stem: _read_json(p) for p in sorted(path.glob('*.json')) if p.stem in SECTIONS}
        if not found:
            raise ValueError(f'{path}: no config files found (expected names such as trackers.json)')
        return found
    if path.is_file():
        if path.stem not in SECTIONS:
            raise ValueError(f'{path}: file name must be one of {", ".join(SECTIONS)} (plus .json)')
        return {path.stem: _read_json(path)}
    raise FileNotFoundError(f'config path not found: {path}')


def _merge_section(section, base, over):
    """Return base with `over` applied. 'key' replaces; '+key' extends a list or updates a dict."""
    if not isinstance(over, Mapping):
        raise TypeError(f'{section}: expected a dict of keys to override, got {type(over).__name__}')
    out = copy.deepcopy(base)
    for key, value in over.items():
        extend = key.startswith('+')
        k = key[1:] if extend else key
        if section not in FREEFORM_SECTIONS and k not in base and k != '_comment':
            valid = ', '.join(x for x in base if not x.startswith('_'))
            raise ValueError(f'{section}: unknown key {k!r} (valid keys: {valid})')
        if extend:
            current = out.get(k)
            if isinstance(current, list):
                out[k] = current + list(copy.deepcopy(value))
            elif isinstance(current, dict):
                out[k] = {**current, **copy.deepcopy(value)}
            elif current is None and section in FREEFORM_SECTIONS:
                out[k] = copy.deepcopy(value)
            else:
                raise TypeError(f"{section}: '+{k}' only works on lists and dicts")
        else:
            out[k] = copy.deepcopy(value)
    return out


class Config:
    """Detection data and options: the JSON files in config/, optionally layered with overrides.

    Each argument is a layer applied in order on top of the defaults:
      * a dict          {'trackers': {'+patterns': [...]}, 'timeout': 5}
      * a path          a directory of <section>.json files, or one <section>.json file
      * a Config        used as the new base
    Keyword arguments are one more dict layer. Within a section a key replaces the default;
    '+key' appends to a list / updates a dict instead. Top-level names that are not sections are
    treated as settings (domain, endpoints, browser, deep, max_scripts, timeout, cache_ttl,
    workers, user_agent, ...).
    """

    _default = None

    def __init__(self, *layers, **options):
        base = Config.default()
        for layer in layers:
            base = base._layered(layer)
        if options:
            base = base._layered(options)
        self._raw, self._compiled, self._lock = base._raw, dict(base._compiled), threading.RLock()

    @classmethod
    def _make(cls, raw, compiled=None):
        self = object.__new__(cls)
        self._raw, self._compiled, self._lock = raw, compiled or {}, threading.RLock()
        return self

    @classmethod
    def default(cls):
        if cls._default is None:
            raw = {}
            for section in SECTIONS:
                path = CONFIG_DIR / f'{section}.json'
                if not path.is_file():
                    raise FileNotFoundError(f'missing config file: {path} (set WEBSPY_CONFIG_DIR to change the location)')
                raw[section] = _read_json(path)
            cls._default = cls._make(raw)
        return cls._default

    def _split(self, mapping):
        overrides = {}
        for key, value in mapping.items():
            if key in SECTIONS:
                overrides[key] = value
                continue
            setting = OPTION_ALIASES.get(key, key)
            if setting not in self._raw['settings']:
                options = sorted(k for k in self._raw['settings'] if not k.startswith('_'))
                raise TypeError(f'unknown option {key!r}. Sections: {", ".join(SECTIONS)}. Options: {", ".join(options)}')
            overrides.setdefault('settings', {})[setting] = value
        return overrides

    def _layered(self, layer):
        if isinstance(layer, Config):
            return layer
        if isinstance(layer, (str, os.PathLike)):
            overrides = _read_path(layer)
        elif isinstance(layer, Mapping):
            overrides = self._split(layer)
        else:
            raise TypeError(f'config layer must be a dict, a path or a Config, not {type(layer).__name__}')
        raw, compiled = dict(self._raw), dict(self._compiled)
        for section, over in overrides.items():
            raw[section] = _merge_section(section, self._raw[section], over)
            compiled.pop(section, None)
        new = Config._make(raw, compiled)
        for section in overrides:
            getattr(new, section)
        return new

    def __getattr__(self, name):
        if name.startswith('_') or name not in SECTIONS:
            raise AttributeError(name)
        with self._lock:
            if name not in self._compiled:
                try:
                    self._compiled[name] = _COMPILERS.get(name, lambda d, n: _ns(d))(self._raw[name], name)
                except (KeyError, TypeError, ValueError) as exc:
                    if isinstance(exc, ValueError):
                        raise
                    raise ValueError(f'{name}.json: malformed entry ({type(exc).__name__}: {exc})') from None
            return self._compiled[name]

    def raw(self, section):
        """A copy of a section's uncompiled data, handy as the starting point for an override."""
        return copy.deepcopy(self._raw[section])

    def __repr__(self):
        return f'Config(sections={len(self._raw)})'


_DEFAULT_SETTINGS = Config.default().settings
DEFAULT_UA = _DEFAULT_SETTINGS['default_user_agent']
BROWSER_UA = _DEFAULT_SETTINGS['browser_user_agent']
CONF_RANK = _DEFAULT_SETTINGS['confidence_rank']
SEVERITY_RANK = _DEFAULT_SETTINGS['severity_rank']
AUDIT_PROFILES = Config.default().profiles.profiles


# ---------------------------------------------------------------------------
# HTML parsing helpers (parser internals, not detection data)
# ---------------------------------------------------------------------------

_TAG_RE = re.compile(
    r'<(script|iframe|frame|img|link|source|embed|object|video|audio|a|area|form)\b([^>]*)>',
    re.IGNORECASE | re.DOTALL
)
_ATTR_RE = re.compile(
    r'([a-zA-Z_:][\w:.\-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'>]+))',
    re.DOTALL
)
_URL_ATTRS = ('src', 'data-src', 'data-lazy-src', 'data-original', 'data-url',
              'href', 'action', 'data', 'poster', 'srcset', 'data-srcset')
_KIND_BY_TAG = {
    'script': 'script', 'iframe': 'iframe', 'frame': 'iframe', 'img': 'img',
    'link': 'link', 'a': 'a', 'area': 'a', 'form': 'form',
}
_CHALLENGE_MARKERS = (
    'just a moment', 'cf-chl', 'attention required', 'checking your browser',
    'ddos protection', 'captcha', 'access denied', 'enable javascript and cookies',
    '_incapsula_', 'perimeterx', 'datadome',
)
_FORM_RE = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r'<(?:input|textarea|select)\b([^>]*)>', re.IGNORECASE | re.DOTALL)
_CSRF_NAME_RE = re.compile(
    r'csrf|xsrf|_token|authenticity_token|nonce|__requestverificationtoken|anti-?forgery',
    re.IGNORECASE
)


def _normalize_text(text):
    if not text:
        return ''
    text = text.replace('\\/', '/')
    text = re.sub(r'\\u002[fF]', '/', text)
    text = re.sub(r'\\x2[fF]', '/', text)
    return html.unescape(text)


def _parse_attrs(raw):
    return {k.lower(): (a or b or c) for k, a, b, c in _ATTR_RE.findall(raw or '')}


def _parse_assets(raw_html, base_url):
    assets = []
    for match in _TAG_RE.finditer(raw_html or ''):
        tag = match.group(1).lower()
        raw_attrs = match.group(2)
        attrs = _parse_attrs(raw_attrs)
        for attr in _URL_ATTRS:
            value = attrs.get(attr)
            if not value:
                continue
            if attr in ('srcset', 'data-srcset'):
                value = value.split(',')[0].strip().split(' ')[0]
            value = value.strip()
            if not value or value.startswith(('#', 'data:', 'javascript:', 'mailto:', 'tel:', 'blob:', 'about:')):
                continue
            absolute = urllib.parse.urljoin(base_url, value)
            parsed = urllib.parse.urlparse(absolute)
            if parsed.scheme not in ('http', 'https') or not parsed.hostname:
                continue
            assets.append({
                'tag': tag,
                'attr': attr,
                'kind': _KIND_BY_TAG.get(tag, 'other'),
                'url': absolute,
                'host': parsed.hostname.lower(),
                'scheme': parsed.scheme,
                'attrs': attrs,
                'raw_attrs': raw_attrs,
            })
    return assets


def _clean_domain(value):
    value = (value or '').strip()
    if '://' in value:
        value = urllib.parse.urlparse(value).hostname or value
    return value.split('/')[0].split(':')[0].lower().rstrip('.')


# ---------------------------------------------------------------------------
# Active-recon data (port/service names, subdomain wordlist, dir-listing markers).
# Hardcoded like the HTML-parser internals above, rather than config-driven, so this
# file stays a drop-in replacement with no new JSON files required.
# ---------------------------------------------------------------------------

COMMON_SCAN_PORTS = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http',
    110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn', 143: 'imap',
    161: 'snmp', 389: 'ldap', 443: 'https', 445: 'microsoft-ds', 465: 'smtps',
    587: 'submission', 631: 'ipp', 993: 'imaps', 995: 'pop3s', 1433: 'mssql',
    1521: 'oracle', 1723: 'pptp', 2049: 'nfs', 2375: 'docker', 2376: 'docker-tls',
    2483: 'oracle-tls', 27017: 'mongodb', 27018: 'mongodb', 27019: 'mongodb-shard',
    28017: 'mongodb-http', 3000: 'dev-http', 3268: 'ldap-gc', 3306: 'mysql',
    3389: 'rdp', 4443: 'https-alt', 5000: 'dev-http', 5432: 'postgresql',
    5601: 'kibana', 5672: 'amqp', 5900: 'vnc', 5984: 'couchdb', 6379: 'redis',
    7001: 'weblogic', 8000: 'dev-http', 8008: 'http-alt', 8080: 'http-proxy',
    8081: 'http-alt', 8086: 'influxdb', 8181: 'http-alt', 8443: 'https-alt',
    8500: 'consul', 8888: 'http-alt', 9000: 'dev-http', 9090: 'prometheus',
    9200: 'elasticsearch', 9300: 'elasticsearch-transport', 9418: 'git',
    11211: 'memcached', 15672: 'rabbitmq-mgmt', 25565: 'minecraft',
}

# service -> (severity, reason), used by derive_findings() for get_port_scan hits.
RISKY_EXPOSED_SERVICES = {
    'ftp': ('medium', 'Unencrypted file-transfer protocol exposed to the internet'),
    'telnet': ('high', 'Unencrypted remote-administration protocol exposed'),
    'rpcbind': ('medium', 'RPC portmapper exposed; often used to enumerate other RPC services'),
    'netbios-ssn': ('medium', 'NetBIOS/SMB-related service exposed to the internet'),
    'microsoft-ds': ('high', 'SMB file sharing exposed to the internet'),
    'snmp': ('medium', 'SNMP exposed; default/weak community strings leak device info'),
    'mssql': ('high', 'Database port exposed to the internet'),
    'oracle': ('high', 'Database port exposed to the internet'),
    'oracle-tls': ('medium', 'Database port exposed to the internet (TLS)'),
    'mysql': ('high', 'Database port exposed to the internet'),
    'postgresql': ('high', 'Database port exposed to the internet'),
    'mongodb': ('high', 'Database port exposed to the internet'),
    'mongodb-shard': ('high', 'Database port exposed to the internet'),
    'mongodb-http': ('medium', 'Database HTTP status interface exposed'),
    'redis': ('high', 'In-memory data store exposed, commonly run without authentication'),
    'couchdb': ('high', 'Database port exposed to the internet'),
    'memcached': ('high', 'Memcached exposed — can leak cached data or be abused for UDP amplification'),
    'elasticsearch': ('high', 'Search/datastore exposed, often without authentication'),
    'elasticsearch-transport': ('medium', 'Elasticsearch cluster transport port exposed'),
    'rdp': ('high', 'Remote desktop exposed to the internet'),
    'vnc': ('high', 'VNC remote desktop exposed to the internet'),
    'docker': ('critical', 'Docker API exposed without TLS — typically full host/container compromise'),
    'docker-tls': ('medium', 'Docker API exposed (TLS-wrapped)'),
    'nfs': ('medium', 'NFS exposed to the internet'),
    'pptp': ('medium', 'Legacy, cryptographically broken VPN protocol exposed'),
    'kibana': ('medium', 'Kibana dashboard exposed'),
    'prometheus': ('medium', 'Prometheus metrics endpoint exposed; often leaks internal topology'),
    'consul': ('high', 'Consul API/UI exposed; can expose service topology and KV data'),
    'rabbitmq-mgmt': ('medium', 'RabbitMQ management UI exposed'),
    'influxdb': ('medium', 'InfluxDB exposed'),
    'git': ('medium', 'git daemon exposed; may allow anonymous repository access'),
    'ldap': ('medium', 'LDAP exposed to the internet'),
    'ldap-gc': ('medium', 'LDAP global catalog exposed to the internet'),
}

COMMON_SUBDOMAINS = [
    'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp',
    'secure', 'vpn', 'api', 'dev', 'staging', 'test', 'portal', 'admin', 'app',
    'cdn', 'static', 'assets', 'img', 'images', 'media', 'files', 'docs', 'help',
    'support', 'status', 'shop', 'store', 'm', 'mobile', 'beta', 'demo', 'sandbox',
    'git', 'gitlab', 'jenkins', 'ci', 'grafana', 'kibana', 'elastic', 'monitor',
    'metrics', 'dashboard', 'login', 'auth', 'sso', 'oauth', 'id', 'accounts',
    'ftp', 'sftp', 'db', 'mysql', 'postgres', 'redis', 'cache', 'search',
    'ws', 'websocket', 'socket', 'cdn1', 'cdn2', 'edge', 'origin', 'internal',
    'intranet', 'extranet', 'vpn1', 'proxy', 'gateway', 'lb', 'old', 'new',
    'legacy', 'archive', 'backup', 'uat', 'qa', 'preprod', 'prod', 'production',
    'www1', 'www2', 'mx', 'mx1', 'mx2', 'email', 'autodiscover', 'autoconfig',
    'ns3', 'ns4', 'dns', 'ntp', 'time', 'ldap', 'ad', 'webdisk', 'cpanel', 'whm',
    'panel', 'control', 'crm', 'erp', 'jira', 'confluence', 'wiki', 'forum',
    'community', 'news', 'press', 'careers', 'jobs', 'hr', 'billing', 'pay',
    'checkout', 'cart', 'graphql', 'api-dev', 'api-staging', 'test-api',
]

COMMON_LISTABLE_PATHS = [
    '/uploads/', '/images/', '/img/', '/files/', '/backup/', '/backups/',
    '/assets/', '/static/', '/media/', '/docs/', '/tmp/', '/temp/', '/data/',
    '/log/', '/logs/', '/old/', '/archive/', '/.well-known/', '/wp-content/uploads/',
    '/download/', '/downloads/', '/export/', '/admin/', '/private/', '/csv/',
]

_DIR_LISTING_RE = re.compile(
    r'<title>\s*Index of /|Index of /[^<]*</title>|\[To Parent Directory\]|'
    r'Directory Listing For|<h1>\s*Index of /',
    re.IGNORECASE,
)

_WHOIS_REFERRAL_RE = re.compile(r'(?:whois|refer):\s*([a-zA-Z0-9.\-]+)', re.IGNORECASE)

# Certificate Transparency: how long (seconds) a failed lookup is remembered, so that
# several probes running in parallel do not all hammer an overloaded service.
CT_FAILURE_TTL = 45
CT_RETRYABLE_STATUS = (429, 500, 502, 503, 504)


class Passive:
    """A set of passive probes bound to one configuration.

    Passive()                          defaults from config/*.json
    Passive(conf, conf, ..., **opts)   layers on top of the defaults (see Config)
    Passive(domain='example.com')      then probes can be called without a domain
    """

    def __init__(self, *confs, **options):
        cfg = Config.default()
        for conf in confs:
            cfg = cfg._layered(conf)
        if options:
            cfg = cfg._layered(options)
        self._setup(cfg)

    def _setup(self, cfg):
        self.cfg = cfg
        s = cfg.settings
        self.domain = _clean_domain(s['domain']) if s.get('domain') else None
        self.ua = s['default_user_agent']
        self.headers = {'User-Agent': self.ua}
        self.browser_headers = {
            'User-Agent': s['browser_user_agent'],
            'Accept': s['browser_accept'],
            'Accept-Language': s['browser_accept_language'],
        }
        self.timeout = s['timeout']
        self.cache_ttl = s['cache_ttl']
        self.conf_rank = s['confidence_rank']
        self.severity_rank = s['severity_rank']
        self._multi_suffixes = set(s['multi_suffixes'])
        self._cache = {}
        # Certificate Transparency results are shared between probes (get_cert_transparency and
        # get_takeover_candidates both need them) and serialised with a lock, so a parallel audit
        # makes one request to the CT service instead of several simultaneous ones.
        self._ct_cache = {}
        self._ct_lock = threading.Lock()

    def clone(self, *confs, **options):
        """A new instance that starts from this one's configuration plus further layers."""
        cfg = self.cfg
        for conf in confs:
            cfg = cfg._layered(conf)
        if options:
            cfg = cfg._layered(options)
        new = object.__new__(type(self))
        new._setup(cfg)
        return new

    def __repr__(self):
        return f'Passive(domain={self.domain!r}, {len(self.cfg.trackers.vendors)} tracker patterns)'

    def clear_cache(self):
        self._cache.clear()
        self._ct_cache.clear()

    def _dom(self, domain=None):
        domain = _clean_domain(domain) if domain else self.domain
        if not domain:
            raise ValueError('no domain given: pass one to the probe or create Passive(domain=...)')
        return domain

    def _endpoints(self, endpoints=None):
        return list(endpoints) if endpoints else list(self.cfg.settings['endpoints'])

    def _opt(self, value, key):
        return self.cfg.settings[key] if value is None else value

    @staticmethod
    def _url(domain, path='/', scheme='https'):
        if not path.startswith('/'):
            path = '/' + path
        return f'{scheme}://{domain}{path}'

    def _get(self, domain, path='/', method='GET', timeout=None, headers=None, **kwargs):
        url = self._url(domain, path)
        timeout = timeout or self.timeout
        req_headers = headers or self.headers
        cache_key = None
        if method == 'GET' and not kwargs and self.cache_ttl > 0:
            cache_key = (url, tuple(sorted(req_headers.items())))
            cached = self._cache.get(cache_key)
            if cached and time.time() - cached[0] < self.cache_ttl:
                return cached[1], None
        try:
            if method == 'POST':
                resp = requests.post(url, headers=req_headers, timeout=timeout, **kwargs)
            elif method == 'OPTIONS':
                resp = requests.options(url, headers=req_headers, timeout=timeout, **kwargs)
            elif method == 'HEAD':
                resp = requests.head(url, headers=req_headers, timeout=timeout, **kwargs)
            else:
                resp = requests.get(url, headers=req_headers, timeout=timeout, **kwargs)
        except requests.RequestException as e:
            return None, str(e)
        if cache_key:
            self._cache[cache_key] = (time.time(), resp)
        return resp, None

    def _get_json_retry(self, url, params=None, timeout=30, attempts=3, backoff=2.0):
        """GET a JSON document from a third-party service, retrying transient failures.

        Retries on timeouts, connection errors, 429/5xx responses and non-JSON bodies (public
        services such as crt.sh answer overload with an HTML error page). Honours Retry-After.
        Client errors (other 4xx) are not retried. Returns (data, error_message).
        """
        host = urllib.parse.urlparse(url).hostname or url
        last = 'unknown error'
        for attempt in range(max(1, attempts)):
            delay = backoff * (2 ** attempt)
            try:
                resp = requests.get(url, params=params, headers=self.headers, timeout=timeout)
                status = resp.status_code
                if status in CT_RETRYABLE_STATUS:
                    last = f'HTTP {status} from {host}'
                    retry_after = resp.headers.get('Retry-After', '')
                    if retry_after.isdigit():
                        delay = float(retry_after)
                elif 400 <= status < 500:
                    return None, f'HTTP {status} from {host}'
                else:
                    if not resp.text.strip():
                        return [], None
                    return resp.json(), None
            except (requests.RequestException, ValueError) as e:
                last = f'{type(e).__name__} from {host}: {e}'
            if attempt < attempts - 1:
                time.sleep(min(delay, 20))
        return None, f'{last} (after {attempts} attempts)'

    def _fetch_page(self, domain, endpoint='/', browser=None):
        browser = self._opt(browser, 'browser')
        return self._get(domain, endpoint, headers=self.browser_headers if browser else self.headers)

    def _fetch_text(self, url, max_bytes=800_000, headers=None, timeout=None):
        try:
            resp = requests.get(url, headers=headers or self.headers, timeout=timeout or self.timeout, stream=True)
        except requests.RequestException:
            return None
        try:
            if resp.status_code != 200:
                return None
            chunks, total = [], 0
            for chunk in resp.iter_content(65536):
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
            return b''.join(chunks).decode(resp.encoding or 'utf-8', errors='replace')
        except requests.RequestException:
            return None
        finally:
            resp.close()

    def _resolver(self, nameservers=None, timeout=5):
        if nameservers is None:
            nameservers = self.cfg.settings['nameservers']
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(nameservers)
        resolver.timeout = timeout
        resolver.lifetime = timeout
        return resolver

    def _dns_query(self, resolver, name, rtype):
        try:
            answer = resolver.resolve(name, rtype)
            return {
                'type': rtype,
                'entries': [{'value': r.to_text(), 'ttl': answer.rrset.ttl} for r in answer],
            }
        except dns.resolver.NXDOMAIN:
            return {'type': rtype, 'error': 'NXDOMAIN'}
        except dns.resolver.NoAnswer:
            return {'type': rtype, 'entries': []}
        except dns.resolver.NoNameservers:
            return {'type': rtype, 'error': 'no nameservers responded'}
        except dns.exception.Timeout:
            return {'type': rtype, 'error': 'timeout'}
        except Exception as e:
            return {'type': rtype, 'error': str(e)}

    def _dns_txt(self, resolver, name):
        try:
            answer = resolver.resolve(name, 'TXT')
        except Exception:
            return []
        return [b''.join(r.strings).decode('utf-8', 'replace') for r in answer]

    def _tls_handshake(self, domain, port=443, timeout=None):
        timeout = timeout or self.timeout
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher_name, tls_version, secret_bits = ssock.cipher()
        return cert, cipher_name, tls_version, secret_bits

    def _grab_banner(self, host, port, timeout, use_tls=False):
        """Connect, optionally TLS-wrap, and return whatever greeting/banner the service sends (or a HEAD probe for plain HTTP-like ports)."""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if use_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock)
                try:
                    data = sock.recv(256)
                except (socket.timeout, OSError):
                    data = b''
                if not data and COMMON_SCAN_PORTS.get(port, '').startswith(('http', 'dev-http')):
                    try:
                        sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
                        data = sock.recv(512)
                    except OSError:
                        pass
                return data.decode('utf-8', 'replace').strip() if data else None
        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
            return None

    def _whois_query(self, server, query, timeout=10):
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((query + '\r\n').encode('utf-8', 'ignore'))
            chunks = []
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        return b''.join(chunks).decode('utf-8', 'replace')

    def _dedup_findings(self, findings, key):
        seen = {}
        for f in findings:
            k = f[key]
            if k not in seen or self.conf_rank[f['confidence']] > self.conf_rank[seen[k]['confidence']]:
                seen[k] = f
        return sorted(seen.values(), key=lambda f: -self.conf_rank[f['confidence']])

    def _base_domain(self, hostname):
        parts = (hostname or '').lower().rstrip('.').split('.')
        if len(parts) >= 3 and '.'.join(parts[-2:]) in self._multi_suffixes:
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:]) if len(parts) >= 2 else (hostname or '')

    def _is_third_party(self, host, domain):
        return self._base_domain(host) != self._base_domain(domain)

    def _match_vendors(self, value, categories=None):
        return [
            (name, cat) for rx, name, cat in self.cfg.trackers.vendors
            if (categories is None or cat in categories) and rx.search(value)
        ]

    def _fetch_scripts(self, assets, domain, max_scripts=None, max_bytes=800_000, headers=None, referer=None):
        max_scripts = self._opt(max_scripts, 'max_scripts')
        seen, candidates = set(), []
        for asset in assets:
            if asset['kind'] == 'script' and asset['attr'] in ('src', 'data-src') and asset['url'] not in seen:
                seen.add(asset['url'])
                candidates.append(asset)

        def priority(asset):
            if re.search(r'gtm\.js|gtag/js|adobedtm|tiqcdn|tagcommander|segment', asset['url'], re.I):
                return 0
            if not self._is_third_party(asset['host'], domain):
                return 1
            return 2

        candidates.sort(key=priority)
        selected = candidates[:max_scripts]
        req_headers = dict(headers or self.browser_headers)
        if referer:
            req_headers['Referer'] = referer

        def fetch(asset):
            text = self._fetch_text(asset['url'], max_bytes, req_headers)
            return (asset['url'], _normalize_text(text)) if text else None

        files = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            for result in pool.map(fetch, selected):
                if result:
                    files.append(result)
        return files

    def _page_context(self, domain, endpoint='/', deep=None, max_scripts=None, browser=None):
        deep = self._opt(deep, 'deep')
        max_scripts = self._opt(max_scripts, 'max_scripts')
        browser = self._opt(browser, 'browser')
        resp, err = self._fetch_page(domain, endpoint, browser)
        if err:
            return {'error': err}
        raw = resp.text or ''
        assets = _parse_assets(raw, resp.url)
        js_files = []
        if deep:
            js_files = self._fetch_scripts(
                assets, domain, max_scripts,
                headers=self.browser_headers if browser else self.headers,
                referer=resp.url,
            )
        csp = ' '.join(filter(None, [
            resp.headers.get('Content-Security-Policy'),
            resp.headers.get('Content-Security-Policy-Report-Only'),
        ]))
        return {
            'resp': resp,
            'raw': raw,
            'text': _normalize_text(raw),
            'assets': assets,
            'js_files': js_files,
            'csp': csp,
        }

    def _diagnostics(self, ctx):
        resp = ctx['resp']
        body = resp.text or ''
        sample = body[:6000].lower()
        blocked = resp.status_code in (401, 403, 429, 451, 503) or (
            len(body) < 30000 and any(m in sample for m in _CHALLENGE_MARKERS)
        )
        script_tags = sum(1 for a in ctx['assets'] if a['kind'] == 'script')
        iframe_tags = sum(1 for a in ctx['assets'] if a['kind'] == 'iframe')
        notes = []
        if blocked:
            notes.append('response looks like a bot challenge or block page; results are likely incomplete')
        if script_tags <= 1 and len(body) < 20000 and not blocked:
            notes.append('very little static HTML; the page probably renders client-side, so ad/tracker '
                         'loaders injected at runtime will not be visible without a headless browser')
        return {
            'status_code': resp.status_code,
            'final_url': resp.url,
            'content_type': resp.headers.get('Content-Type'),
            'body_length': len(body),
            'script_tags': script_tags,
            'iframe_tags': iframe_tags,
            'js_files_scanned': [u for u, _ in ctx['js_files']],
            'blocked_suspected': blocked,
            'notes': notes,
        }

    def _scan_vendors(self, ctx, categories=None):
        found = {}

        def hit(name, category, source, sample):
            entry = found.setdefault(name, {'name': name, 'category': category, 'sources': {}, 'samples': []})
            entry['sources'][source] = entry['sources'].get(source, 0) + 1
            if sample and sample not in entry['samples'] and len(entry['samples']) < 5:
                entry['samples'].append(sample[:140])

        for rx, name, category in self.cfg.trackers.vendors:
            if categories is not None and category not in categories:
                continue
            for m in rx.finditer(ctx['text']):
                hit(name, category, 'html', m.group(0))
            for asset in ctx['assets']:
                if rx.search(asset['url']):
                    hit(name, category, asset['kind'] + '_url', asset['host'])
            for url, js_text in ctx['js_files']:
                js_host = urllib.parse.urlparse(url).hostname or url
                for m in rx.finditer(js_text):
                    hit(name, category, 'js_file', f'{js_host}: {m.group(0)}')
            if ctx['csp']:
                for m in rx.finditer(ctx['csp']):
                    hit(name, category, 'csp', m.group(0))

        strong = ('script_url', 'iframe_url', 'img_url', 'js_file')
        for v in found.values():
            s = v['sources']
            v['total_hits'] = s.get('html', 0) + s.get('js_file', 0) + s.get('csp', 0)
            v['script_tag_hits'] = s.get('script_url', 0)
            v['iframe_hits'] = s.get('iframe_url', 0)
            if any(k in s for k in strong) or s.get('html', 0) >= 2:
                v['confidence'] = 'high'
            elif 'html' in s:
                v['confidence'] = 'medium'
            else:
                v['confidence'] = 'low'
        return sorted(
            found.values(),
            key=lambda v: (-self.conf_rank[v['confidence']], -v['total_hits'], v['name'])
        )

    def _baseline(self, domain):
        probe = '/webspy-' + secrets.token_hex(6) + '-nonexistent'
        resp, err = self._get(domain, probe, allow_redirects=False)
        if err:
            return None
        return {
            'status_code': resp.status_code,
            'content_type': (resp.headers.get('Content-Type') or '').split(';')[0],
            'sha1': hashlib.sha1(resp.content).hexdigest(),
            'length': len(resp.content),
        }

    def get_page_info(self, domain=None, endpoints=None):
        """Status code and full response headers per endpoint."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue
            output['value'][endpoint] = {
                'status_code': resp.status_code,
                'headers': dict(resp.headers),
            }
        return output

    def get_cors(self, domain=None, endpoints=None, origin=None):
        """CORS behaviour for an arbitrary Origin: reflection, credentials, Vary."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        origin = (origin or self.cfg.http_checks.cors_probe['origins'][0]).replace('{host}', domain)
        headers = {"Origin": origin, "User-Agent": self.ua}
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint, headers=headers)
            if err:
                output['value'][endpoint] = {'error': err}
                continue
            allow_origin = resp.headers.get("Access-Control-Allow-Origin")
            allow_creds = resp.headers.get("Access-Control-Allow-Credentials")
            vary = resp.headers.get("Vary", "")
            if allow_origin:
                output['value'][endpoint] = {
                    'status_code': resp.status_code,
                    'CORS': True,
                    'allow_origin': allow_origin,
                    'reflects_origin': allow_origin == origin,
                    'allow_credentials': (allow_creds or "").lower() == "true",
                    'origin_in_vary': 'origin' in vary.lower(),
                }
            else:
                output['value'][endpoint] = {'status_code': resp.status_code, 'CORS': False}
        return output

    def get_sitemap(self, domain=None, engine='generic'):
        """Fetch API/site maps for a named engine (wp, swagger, openapi, actuator, graphql, robots, generic)."""
        domain = self._dom(domain)
        output = {'domain': domain, 'engine': engine, 'time': time.time(), 'value': {}}

        def _fetch(path, as_json=True, method='GET', json_body=None):
            resp, err = self._get(domain, path, method=method, json=json_body)
            if err:
                return {'path': path, 'error': err}
            entry = {'path': path, 'status_code': resp.status_code}
            if as_json:
                try:
                    entry['data'] = resp.json()
                except (ValueError, json.JSONDecodeError):
                    entry['data'] = None
                    entry['note'] = 'non-JSON response'
            else:
                entry['data'] = resp.text
            return entry

        if engine == 'wp':
            output['value'] = _fetch('/wp-json/')
        elif engine == 'swagger':
            for path in ['/swagger.json', '/swagger/v1/swagger.json', '/api/swagger.json']:
                result = _fetch(path)
                if result.get('status_code') == 200 and result.get('data'):
                    output['value'] = result
                    break
            else:
                output['value'] = {'found': False}
        elif engine == 'openapi':
            for path in ['/openapi.json', '/v1/openapi.json', '/api/openapi.json']:
                result = _fetch(path)
                if result.get('status_code') == 200 and result.get('data'):
                    output['value'] = result
                    break
            else:
                output['value'] = {'found': False}
        elif engine == 'actuator':
            mappings = _fetch('/actuator/mappings')
            output['value'] = mappings if mappings.get('status_code') == 200 else _fetch('/actuator')
        elif engine == 'graphql':
            introspection_query = self.cfg.graphql.introspection_query
            for path in ['/graphql', '/api/graphql', '/v1/graphql']:
                result = _fetch(path, method='POST', json_body=introspection_query)
                if result.get('status_code') == 200 and result.get('data'):
                    output['value'] = result
                    break
            else:
                output['value'] = {'found': False}
        elif engine == 'robots':
            result = _fetch('/robots.txt', as_json=False)
            if result.get('data'):
                result['sitemap_urls'] = [
                    line.split(':', 1)[1].strip()
                    for line in result['data'].splitlines()
                    if line.lower().startswith('sitemap:')
                ]
            output['value'] = result
        elif engine == 'generic':
            found = {}
            for path in ['/wp-json/', '/swagger.json', '/openapi.json', '/api/openapi.json',
                         '/actuator/mappings', '/graphql', '/api-docs', '/redoc',
                         '/.well-known/openapi.json', '/robots.txt', '/sitemap.xml']:
                result = _fetch(path, as_json=not path.endswith(('.txt', '.xml')))
                if result.get('status_code') and result['status_code'] < 400:
                    found[path] = result
            output['value'] = found
        else:
            output['value'] = {'error': f'unknown engine: {engine}'}
        return output

    def get_cookies(self, domain=None, endpoints=None):
        """Set-Cookie attributes: Secure, HttpOnly, SameSite, expiry, scope."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue

            try:
                raw_cookies = resp.raw.headers.getlist('Set-Cookie')
            except AttributeError:
                raw_cookies = []

            cookies = []
            for raw in raw_cookies:
                c = http.cookies.SimpleCookie()
                try:
                    c.load(raw)
                except http.cookies.CookieError:
                    cookies.append({'raw': raw, 'error': 'failed to parse'})
                    continue
                for name, morsel in c.items():
                    cookies.append({
                        'name': name,
                        'value_length': len(morsel.value) if morsel.value else 0,
                        'secure': bool(morsel['secure']),
                        'httponly': bool(morsel['httponly']),
                        'samesite': morsel['samesite'] or None,
                        'expires': morsel['expires'] or None,
                        'max_age': morsel['max-age'] or None,
                        'domain': morsel['domain'] or None,
                        'path': morsel['path'] or None,
                        'session_cookie': not bool(morsel['expires'] or morsel['max-age']),
                    })
            output['value'][endpoint] = cookies
        return output

    def get_trackers(self, domain=None, endpoints=None, include_unclassified=True, deep=None,
                     max_scripts=None, browser=None):
        """Analytics, ads, replay, chat, A/B, monitoring, fingerprinting, consent and abuse scripts, with evidence and confidence."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        for endpoint in endpoints:
            ctx = self._page_context(domain, endpoint, deep, max_scripts, browser)
            if 'error' in ctx:
                output['value'][endpoint] = {'error': ctx['error']}
                continue

            vendors = self._scan_vendors(ctx)
            by_category = {}
            for v in vendors:
                by_category.setdefault(v['category'], set()).add(v['name'])

            entry = {
                'by_category': {cat: sorted(names) for cat, names in by_category.items()},
                'all': sorted({v['name'] for v in vendors}),
                'vendors': vendors,
                'diagnostics': self._diagnostics(ctx),
            }

            if include_unclassified:
                unclassified = set()
                for asset in ctx['assets']:
                    if asset['kind'] not in ('script', 'iframe'):
                        continue
                    host = asset['host']
                    if not self._is_third_party(host, domain) or self.cfg.trackers.known_infra.search(host):
                        continue
                    if self._match_vendors(asset['url']):
                        continue
                    unclassified.add(host)
                entry['unclassified_third_party_hosts'] = sorted(unclassified)

            output['value'][endpoint] = entry
        return output

    def get_ad_syndicates(self, domain=None, endpoint='/', deep=None, max_scripts=None,
                          include_ads_txt=True, browser=None):
        """Advertising networks, exchanges, native/affiliate/aggressive networks and ad-slot markers, via HTML, iframes, linked JS, CSP and ads.txt."""
        domain = self._dom(domain)
        output = {'domain': domain, 'endpoint': endpoint, 'time': time.time(), 'value': {}}

        ctx = self._page_context(domain, endpoint, deep, max_scripts, browser)
        if 'error' in ctx:
            output['value'] = {'error': ctx['error']}
            return output

        vendors = self._scan_vendors(ctx, self.cfg.trackers.ad_categories)

        iframe_hosts, script_hosts, heuristic = set(), set(), set()
        for asset in ctx['assets']:
            if asset['kind'] not in ('script', 'iframe', 'img', 'link'):
                continue
            matched = self._match_vendors(asset['url'], self.cfg.trackers.ad_categories)
            if matched:
                if asset['kind'] == 'iframe':
                    iframe_hosts.add(asset['host'])
                elif asset['kind'] == 'script':
                    script_hosts.add(asset['host'])
                continue
            host = asset['host']
            if (self._is_third_party(host, domain)
                    and not self.cfg.trackers.known_infra.search(host)
                    and not self._match_vendors(asset['url'])
                    and self.cfg.trackers.ad_like_host.search(host)):
                heuristic.add(host)

        text = ctx['text']
        slot_markers = {
            'adsense_ins_tags': len(re.findall(r'<ins\b[^>]*class=["\'][^"\']*adsbygoogle', text, re.I)),
            'gpt_slot_divs': len(re.findall(r'id=["\']div-gpt-ad', text, re.I)),
            'data_ad_slot_attrs': len(re.findall(r'\bdata-ad-slot=', text, re.I)),
        }

        publisher_ids = set()
        for source in [text] + [t for _, t in ctx['js_files']]:
            for m in re.finditer(r'\b(?:ca-)?(pub-\d{10,20})\b', source):
                publisher_ids.add(m.group(1))

        by_category = {}
        for v in vendors:
            by_category[v['category']] = by_category.get(v['category'], 0) + 1

        value = {
            'vendors': vendors,
            'vendor_count': len(vendors),
            'total_ad_references': sum(v['total_hits'] for v in vendors),
            'by_category': by_category,
            'iframe_ad_hosts': sorted(iframe_hosts),
            'script_ad_hosts': sorted(script_hosts),
            'heuristic_ad_hosts': sorted(heuristic),
            'ad_slot_markers': slot_markers,
            'publisher_ids': sorted(publisher_ids),
            'diagnostics': self._diagnostics(ctx),
        }

        if include_ads_txt:
            ads = self.get_ads_txt(domain, files=('/ads.txt',))['value'].get('/ads.txt', {})
            value['ads_txt'] = {
                'present': ads.get('present', False),
                'summary': ads.get('summary'),
                'sellers': (ads.get('sellers') or [])[:30],
            }

        output['value'] = value
        return output

    def get_ads_txt(self, domain=None, files=('/ads.txt', '/app-ads.txt')):
        """Parse ads.txt / app-ads.txt: authorised sellers, DIRECT vs RESELLER, publisher account IDs."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        for path in files:
            resp, err = self._fetch_page(domain, path)
            if err:
                output['value'][path] = {'present': False, 'error': err}
                continue
            ctype = (resp.headers.get('Content-Type') or '').lower()
            if resp.status_code != 200 or 'html' in ctype:
                output['value'][path] = {'present': False, 'status_code': resp.status_code}
                continue

            variables, records = {}, []
            for line in (resp.text or '').splitlines():
                line = line.split('#', 1)[0].strip()
                if not line:
                    continue
                if ',' not in line and '=' in line:
                    k, _, v = line.partition('=')
                    variables[k.strip().lower()] = v.strip()
                    continue
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 3:
                    records.append({
                        'seller_domain': parts[0].lower(),
                        'account_id': parts[1],
                        'relationship': parts[2].upper(),
                        'certification_id': parts[3] if len(parts) > 3 else None,
                    })

            sellers = {}
            for r in records:
                s = sellers.setdefault(r['seller_domain'], {
                    'seller_domain': r['seller_domain'],
                    'vendor': self.cfg.ads_txt.sellers.get(r['seller_domain']),
                    'direct': 0, 'reseller': 0, 'account_ids': set(),
                })
                if r['relationship'] == 'DIRECT':
                    s['direct'] += 1
                elif r['relationship'] == 'RESELLER':
                    s['reseller'] += 1
                s['account_ids'].add(r['account_id'])

            seller_list = sorted(
                ({**s, 'account_ids': sorted(s['account_ids'])} for s in sellers.values()),
                key=lambda s: -(s['direct'] + s['reseller'])
            )
            output['value'][path] = {
                'present': True,
                'status_code': resp.status_code,
                'variables': variables,
                'sellers': seller_list,
                'summary': {
                    'total_records': len(records),
                    'direct': sum(1 for r in records if r['relationship'] == 'DIRECT'),
                    'reseller': sum(1 for r in records if r['relationship'] == 'RESELLER'),
                    'unique_sellers': len(sellers),
                    'unique_account_ids': len({r['account_id'] for r in records}),
                },
            }
        return output

    def get_identifiers(self, domain=None, endpoints=None, deep=None, max_scripts=None, browser=None):
        """Extract tracking/ad/pixel IDs, emails, social profiles and crypto addresses for linking related sites."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        for endpoint in endpoints:
            ctx = self._page_context(domain, endpoint, deep, max_scripts, browser)
            if 'error' in ctx:
                output['value'][endpoint] = {'error': ctx['error']}
                continue

            sources = [ctx['text']] + [t for _, t in ctx['js_files']]
            identifiers = {}
            for key, rx in self.cfg.identifiers.patterns.items():
                values = set()
                for source in sources:
                    for m in rx.finditer(source):
                        val = next((g for g in m.groups() if g), None) if rx.groups else m.group(0)
                        if val:
                            values.add(val)
                if values:
                    identifiers[key] = sorted(values)

            emails = set()
            for m in re.finditer(r'[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)*\.[a-zA-Z]{2,}', ctx['text']):
                value = m.group(0).lower()
                if value.rsplit('.', 1)[-1] not in ('png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'css', 'js', 'woff', 'woff2'):
                    emails.add(value)

            social = set()
            for asset in ctx['assets']:
                if asset['kind'] == 'a' and any(
                    asset['host'] == h or asset['host'].endswith('.' + h) for h in self.cfg.identifiers.social_hosts
                ):
                    social.add(asset['url'])

            output['value'][endpoint] = {
                'identifiers': identifiers,
                'emails': sorted(emails),
                'social_links': sorted(social),
                'js_files_scanned': [u for u, _ in ctx['js_files']],
            }
        return output

    def get_external_resources(self, domain=None, endpoints=None, browser=None):
        """Third-party host inventory by resource type, vendor attribution, mixed content and outbound link hosts."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        for endpoint in endpoints:
            ctx = self._page_context(domain, endpoint, deep=False, browser=browser)
            if 'error' in ctx:
                output['value'][endpoint] = {'error': ctx['error']}
                continue

            page_https = ctx['resp'].url.startswith('https://')
            hosts, outbound, mixed = {}, {}, []
            for asset in ctx['assets']:
                host = asset['host']
                third_party = self._is_third_party(host, domain)
                if asset['kind'] == 'a':
                    if third_party:
                        outbound[host] = outbound.get(host, 0) + 1
                    continue
                if asset['kind'] == 'form':
                    continue
                if not third_party:
                    pass
                else:
                    entry = hosts.setdefault(host, {'host': host, 'resources': {}, 'vendors': set()})
                    entry['resources'][asset['kind']] = entry['resources'].get(asset['kind'], 0) + 1
                    for name, _ in self._match_vendors(asset['url']):
                        entry['vendors'].add(name)
                if page_https and asset['scheme'] == 'http':
                    rel = (asset['attrs'].get('rel') or '').lower()
                    active = asset['kind'] in ('script', 'iframe') or (asset['kind'] == 'link' and 'stylesheet' in rel)
                    if asset['kind'] in ('script', 'iframe', 'img') or (asset['kind'] == 'link' and 'stylesheet' in rel):
                        mixed.append({'url': asset['url'], 'type': asset['kind'], 'active': active})

            host_list = []
            for entry in hosts.values():
                if entry['vendors']:
                    classification = 'known_vendor'
                elif self.cfg.trackers.known_infra.search(entry['host']):
                    classification = 'infrastructure'
                else:
                    classification = 'unknown'
                host_list.append({
                    'host': entry['host'],
                    'classification': classification,
                    'vendors': sorted(entry['vendors']),
                    'resources': entry['resources'],
                })
            host_list.sort(key=lambda h: (h['classification'] != 'unknown', h['host']))

            output['value'][endpoint] = {
                'third_party_hosts': host_list,
                'outbound_link_hosts': dict(sorted(outbound.items(), key=lambda kv: -kv[1])),
                'mixed_content': mixed,
                'summary': {
                    'third_party_host_count': len(host_list),
                    'unknown_host_count': sum(1 for h in host_list if h['classification'] == 'unknown'),
                    'mixed_content_count': len(mixed),
                    'active_mixed_content_count': sum(1 for m in mixed if m['active']),
                },
            }
        return output

    def get_forms(self, domain=None, endpoints=None, browser=None):
        """Form inventory: action, method, password/file fields, CSRF token hints, insecure or cross-site actions."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        for endpoint in endpoints:
            resp, err = self._fetch_page(domain, endpoint, browser)
            if err:
                output['value'][endpoint] = {'error': err}
                continue
            forms = []
            for m in _FORM_RE.finditer(resp.text or ''):
                attrs = _parse_attrs(m.group(1))
                action = urllib.parse.urljoin(resp.url, attrs.get('action') or resp.url)
                parsed = urllib.parse.urlparse(action)
                inputs = []
                for im in _INPUT_RE.finditer(m.group(2)):
                    ia = _parse_attrs(im.group(1))
                    inputs.append({
                        'name': ia.get('name'),
                        'type': (ia.get('type') or 'text').lower(),
                        'autocomplete': ia.get('autocomplete'),
                    })
                forms.append({
                    'action': action,
                    'method': (attrs.get('method') or 'GET').upper(),
                    'enctype': attrs.get('enctype'),
                    'input_count': len(inputs),
                    'inputs': inputs[:30],
                    'has_password': any(i['type'] == 'password' for i in inputs),
                    'has_file_upload': any(i['type'] == 'file' for i in inputs),
                    'csrf_token_field': any(i['name'] and _CSRF_NAME_RE.search(i['name']) for i in inputs),
                    'insecure_action': parsed.scheme == 'http',
                    'external_action': self._is_third_party(parsed.hostname or '', domain),
                })
            output['value'][endpoint] = {'forms': forms, 'form_count': len(forms)}
        return output

    def get_security(self, domain=None, endpoints=None):
        """Presence of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy and friends."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        http = self.cfg.http_checks
        security_headers = http.security_headers
        required = http.required_security_headers

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue
            headers = resp.headers
            entry = {}
            missing = []
            for header_name, label in security_headers.items():
                val = headers.get(header_name)
                if header_name in required:
                    entry[header_name] = {'present': val is not None, 'value': val}
                    if val is None:
                        missing.append(label)
                elif val is not None:
                    entry[header_name] = {'present': True, 'value': val}
            entry['summary'] = {'missing_count': len(missing), 'missing': missing}
            output['value'][endpoint] = entry
        return output

    def get_csp_policy(self, domain=None, endpoints=None):
        """Parsed CSP directives with flags for unsafe-inline, unsafe-eval, wildcards and data: sources."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue

            csp_header = resp.headers.get('Content-Security-Policy') or resp.headers.get('Content-Security-Policy-Report-Only')
            report_only = 'Content-Security-Policy' not in resp.headers and 'Content-Security-Policy-Report-Only' in resp.headers

            if not csp_header:
                output['value'][endpoint] = {'present': False}
                continue

            directives = {}
            for part in csp_header.split(';'):
                part = part.strip()
                if not part:
                    continue
                tokens = part.split()
                directives[tokens[0]] = tokens[1:]

            flags = []
            for directive, sources in directives.items():
                if "'unsafe-inline'" in sources:
                    flags.append(f"{directive} allows 'unsafe-inline'")
                if "'unsafe-eval'" in sources:
                    flags.append(f"{directive} allows 'unsafe-eval'")
                if '*' in sources:
                    flags.append(f"{directive} allows wildcard (*) source")
                if "data:" in sources and directive in ('script-src', 'default-src'):
                    flags.append(f"{directive} allows data: URIs")

            output['value'][endpoint] = {
                'present': True,
                'report_only': report_only,
                'raw': csp_header,
                'directives': directives,
                'flags': flags,
            }
        return output

    def get_server_info(self, domain=None, endpoints=None):
        """Server, X-Powered-By, X-AspNet-Version and Via headers."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue
            output['value'][endpoint] = {
                'status_code': resp.status_code,
                'server': resp.headers.get('Server'),
                'x_powered_by': resp.headers.get('X-Powered-By'),
                'x_aspnet_version': resp.headers.get('X-AspNet-Version'),
                'via': resp.headers.get('Via'),
                'disclosure_headers': {
                    h: resp.headers[h] for h in self.cfg.http_checks.info_disclosure_headers if h in resp.headers
                },
            }
        return output

    def get_tech_fingerprint(self, domain=None, endpoints=None):
        """Frontend fingerprint: generator tag, CMS/platform and JS library versions."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue
            body = resp.text or ''

            generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
            cms_platform = [name for rx, name in self.cfg.cms_signatures.body if rx.search(body)]

            seen_libs = {}
            for rx, name in self.cfg.cms_signatures.js_libraries:
                match = rx.search(body)
                if match and name not in seen_libs:
                    seen_libs[name] = match.group(1) if match.groups() and match.group(1) else None

            generator = generator_match.group(1) if generator_match else None
            cms = self.cfg.cms_signatures
            if generator:
                for rx, name in cms.meta_generator:
                    m = rx.search(generator)
                    if m and name not in cms_platform:
                        cms_platform.append(name)
            for header, rx, name in cms.headers:
                value = resp.headers.get(header)
                if value and rx.search(value) and name not in cms_platform:
                    cms_platform.append(name)

            output['value'][endpoint] = {
                'generator_tag': generator,
                'cms_platform': cms_platform,
                'js_libraries': [{'library': n, 'version': v} for n, v in seen_libs.items()],
            }
        return output

    def get_engine_detection(self, domain=None, endpoints=None):
        """Backend language/framework inference from headers, cookie names, generator tags and URL extensions."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue

            headers = resp.headers
            body = resp.text or ''
            cookie_names = list(resp.cookies.keys())
            set_cookie_raw = headers.get('Set-Cookie', '')

            findings = []

            def add(engine, confidence, reason):
                findings.append({'engine': engine, 'confidence': confidence, 'evidence': reason})

            eng = self.cfg.engine_detection
            server = (headers.get('Server') or '').lower()
            for needle, engine, conf in eng.server_checks:
                if needle in server:
                    add(engine, conf, f"Server header: {headers.get('Server')}")

            powered_by = (headers.get('X-Powered-By') or '').lower()
            for needle, engine, conf in eng.powered_by_checks:
                if needle in powered_by:
                    add(engine, conf, f"X-Powered-By: {headers.get('X-Powered-By')}")

            for header, rx, engine, conf in eng.header_checks:
                value = headers.get(header)
                if value and rx.search(value):
                    add(engine, conf, f"{header}: {value}")
            for header, rx, name in self.cfg.cms_signatures.headers:
                value = headers.get(header)
                if value and rx.search(value):
                    add(name, 'high', f"{header}: {value}")

            cookie_blob = set_cookie_raw + ' ' + ' '.join(cookie_names)
            for rx, engine, conf in eng.cookie_checks:
                if rx.search(cookie_blob):
                    add(engine, conf, f"Cookie pattern matched: {rx.pattern}")

            generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
            if generator_match:
                gen_value = generator_match.group(1)
                add(f'Generator meta tag: {gen_value}', 'high', f'<meta name="generator" content="{gen_value}">')

            for rx, name in self.cfg.cms_signatures.body:
                if rx.search(body):
                    add(name, 'high', f"Body pattern matched: {rx.pattern}")

            for rx, engine, conf in eng.extension_checks:
                if rx.search(body):
                    add(engine, conf, f"Linked resource extension pattern matched: {rx.pattern}")

            output['value'][endpoint] = {
                'findings': self._dedup_findings(findings, 'engine'),
                'raw_signals': {
                    'status_code': resp.status_code,
                    'server_header': headers.get('Server'),
                    'x_powered_by': headers.get('X-Powered-By'),
                    'cookie_names': cookie_names,
                },
            }
        return output

    def get_waf_detection(self, domain=None, endpoints=None):
        """WAF/edge vendor signatures from headers, cookies and block-page bodies."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        waf = self.cfg.waf_detection

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue

            headers = resp.headers
            body = resp.text or ''
            cookie_names = list(resp.cookies.keys())
            findings = []

            def add(waf, confidence, reason):
                findings.append({'waf': waf, 'confidence': confidence, 'evidence': reason})

            header_keys_lower = {k.lower(): v for k, v in headers.items()}
            for header_name, vendor in self.cfg.edge_vendors.headers:
                if header_name in header_keys_lower:
                    add(vendor, 'high', f"{header_name}: {header_keys_lower[header_name]}")
            for header_name, vendor, conf in waf.only_headers:
                if header_name in header_keys_lower:
                    add(vendor, conf, f"{header_name}: {header_keys_lower[header_name]}")

            server = (headers.get('Server') or '').lower()
            for needle, vendor in waf.server_checks:
                if needle in server:
                    add(vendor, 'high', f"Server header: {headers.get('Server')}")

            cookie_blob = ' '.join(cookie_names).lower()
            for pattern, vendor in waf.cookie_checks:
                if pattern in cookie_blob:
                    add(vendor, 'high', f"Cookie name pattern matched: {pattern}")

            if resp.status_code >= 400:
                for rx, vendor in waf.block_pages:
                    if rx.search(body):
                        add(vendor, 'high', f"Block-page body pattern matched (status {resp.status_code})")

            output['value'][endpoint] = {
                'findings': self._dedup_findings(findings, 'waf'),
                'raw_signals': {
                    'status_code': resp.status_code,
                    'cookie_names': cookie_names,
                },
            }
        return output

    def get_tls_info(self, domain=None, port=443):
        """Certificate issuer, subject, SANs, validity window, negotiated TLS version and cipher."""
        domain = self._dom(domain)
        output = {'domain': domain, 'port': port, 'time': time.time(), 'value': {}}
        try:
            cert, cipher_name, tls_version, secret_bits = self._tls_handshake(domain, port)
        except ssl.SSLCertVerificationError as e:
            output['value'] = {'error': f'cert verification failed: {e}'}
            return output
        except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
            output['value'] = {'error': str(e)}
            return output
        except ssl.SSLError as e:
            output['value'] = {'error': f'TLS error: {e}'}
            return output
        except Exception as e:
            output['value'] = {'error': str(e)}
            return output

        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        sans = [v for k, v in cert.get('subjectAltName', []) if k == 'DNS']

        not_after = cert.get('notAfter')
        days_remaining = None
        if not_after:
            try:
                days_remaining = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
            except ValueError:
                pass

        output['value'] = {
            'issuer': issuer,
            'subject': subject,
            'sans': sans,
            'not_before': cert.get('notBefore'),
            'not_after': not_after,
            'days_remaining': days_remaining,
            'expired': days_remaining is not None and days_remaining < 0,
            'tls_version': tls_version,
            'cipher': cipher_name,
            'cipher_bits': secret_bits,
        }
        return output

    def get_cache_headers(self, domain=None, endpoints=None):
        """Cache-Control, ETag, Expires and risk flags for cacheable sensitive responses."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        sensitive_keywords = self.cfg.content_checks.sensitive_cache_keywords

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue

            headers = resp.headers
            cache_control = headers.get('Cache-Control', '')
            cc_lower = cache_control.lower()
            no_store = 'no-store' in cc_lower
            is_private = 'private' in cc_lower
            cacheable_by_shared_cache = not no_store and not is_private
            looks_sensitive = any(kw in endpoint.lower() for kw in sensitive_keywords)

            risk_flags = []
            if cacheable_by_shared_cache and looks_sensitive:
                risk_flags.append('Path suggests sensitive content and response is cacheable by shared/proxy caches')
            if cacheable_by_shared_cache and 'Set-Cookie' in headers:
                risk_flags.append('Response sets a cookie but is cacheable — risk of session data being cached')
            if not cache_control and not headers.get('Expires'):
                risk_flags.append('No Cache-Control or Expires header present')

            output['value'][endpoint] = {
                'status_code': resp.status_code,
                'cache_control': cache_control or None,
                'etag': headers.get('ETag'),
                'expires': headers.get('Expires'),
                'last_modified': headers.get('Last-Modified'),
                'pragma': headers.get('Pragma'),
                'vary': headers.get('Vary'),
                'no_store': no_store,
                'private': is_private,
                'has_set_cookie': 'Set-Cookie' in headers,
                'risk_flags': risk_flags,
            }
        return output

    def get_allowed_methods(self, domain=None, endpoints=None):
        """OPTIONS Allow header with risky methods called out."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        risky_methods = self.cfg.http_checks.risky_methods

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint, method='OPTIONS')
            if err:
                output['value'][endpoint] = {'error': err}
                continue
            allow_header = resp.headers.get('Allow', '')
            methods = [m.strip().upper() for m in allow_header.split(',') if m.strip()]
            output['value'][endpoint] = {
                'status_code': resp.status_code,
                'allow_header': allow_header or None,
                'methods': methods,
                'risky_methods_present': {m: risky_methods[m] for m in methods if m in risky_methods},
            }
        return output

    def get_robots_sitemap(self, domain=None):
        """robots.txt rules, sitemap discovery and security.txt presence."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        def _fetch(path):
            resp, err = self._get(domain, path)
            if err:
                return {'error': err}
            return {'status_code': resp.status_code, 'body': resp.text if resp.status_code == 200 else None}

        robots = _fetch('/robots.txt')
        disallowed, allowed, sitemap_urls, user_agents = [], [], [], set()
        if robots.get('body'):
            for line in robots['body'].splitlines():
                line = line.strip()
                if not line or line.startswith('#') or ':' not in line:
                    continue
                key, _, val = line.partition(':')
                key, val = key.strip().lower(), val.strip()
                if key == 'disallow' and val:
                    disallowed.append(val)
                elif key == 'allow' and val:
                    allowed.append(val)
                elif key == 'sitemap':
                    sitemap_urls.append(val)
                elif key == 'user-agent':
                    user_agents.add(val)

        output['value']['robots_txt'] = {
            'present': robots.get('status_code') == 200,
            'status_code': robots.get('status_code'),
            'error': robots.get('error'),
            'disallowed_paths': disallowed,
            'allowed_paths': allowed,
            'sitemap_urls_declared': sitemap_urls,
            'user_agents_referenced': sorted(user_agents),
        }

        sitemap_results = {}
        for sm_url in ['/sitemap.xml', '/sitemap_index.xml'] + sitemap_urls:
            full_url = sm_url if sm_url.startswith('http') else self._url(domain, sm_url)
            try:
                resp = requests.get(full_url, headers=self.headers, timeout=self.timeout)
                if resp.status_code == 200:
                    sitemap_results[full_url] = {
                        'status_code': resp.status_code,
                        'url_entries_found': resp.text.lower().count('<loc>'),
                    }
                else:
                    sitemap_results[full_url] = {'status_code': resp.status_code}
            except requests.RequestException as e:
                sitemap_results[full_url] = {'error': str(e)}
        output['value']['sitemaps'] = sitemap_results

        output['value']['security_txt'] = {}
        for path in ['/.well-known/security.txt', '/security.txt']:
            result = _fetch(path)
            output['value']['security_txt'][path] = {
                'present': result.get('status_code') == 200,
                'status_code': result.get('status_code'),
                'body': result.get('body'),
            }
        return output

    def get_status_map(self, domain=None, endpoints=None):
        """Status code per endpoint with 401/403/5xx clustering."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}, 'summary': {}}
        status_buckets = {}

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint, allow_redirects=False)
            if err:
                status = 'error'
                output['value'][endpoint] = {'error': err}
            else:
                status = resp.status_code
                output['value'][endpoint] = {'status_code': status}
            status_buckets.setdefault(status, []).append(endpoint)

        clusters = {str(k): v for k, v in status_buckets.items() if len(v) >= 2}
        notable = {
            str(k): v for k, v in status_buckets.items()
            if isinstance(k, int) and (k in (401, 403) or 500 <= k < 600)
        }
        output['summary'] = {
            'total_checked': len(endpoints),
            'status_clusters': clusters,
            'notable_403_401_5xx': notable,
        }
        return output

    def get_server_redirects(self, domain=None, endpoint='/', scheme='https'):
        """Server-side redirect chain with hop count, loop detection and final URL."""
        domain = self._dom(domain)
        output = {
            'domain': domain,
            'time': time.time(),
            'value': {'chain': [], 'hop_count': 0, 'final_url': None, 'final_status_code': None},
        }

        current_url = self._url(domain, endpoint, scheme)
        max_hops = 20
        seen_urls = set()

        for _ in range(max_hops):
            try:
                resp = requests.get(current_url, timeout=self.timeout, headers=self.headers, allow_redirects=False)
            except requests.RequestException as e:
                output['value']['chain'].append({'url': current_url, 'error': str(e)})
                break

            output['value']['chain'].append({
                'url': current_url,
                'status_code': resp.status_code,
                'location': resp.headers.get('Location'),
            })

            if resp.status_code not in (301, 302, 303, 307, 308):
                output['value']['final_url'] = current_url
                output['value']['final_status_code'] = resp.status_code
                break

            location = resp.headers.get('Location')
            if not location:
                output['value']['final_url'] = current_url
                output['value']['final_status_code'] = resp.status_code
                break

            next_url = urllib.parse.urljoin(current_url, location)
            if next_url in seen_urls:
                output['value']['loop_detected'] = True
                output['value']['final_url'] = current_url
                output['value']['final_status_code'] = resp.status_code
                break

            seen_urls.add(current_url)
            current_url = next_url
        else:
            output['value']['max_hops_exceeded'] = True
            output['value']['final_url'] = current_url

        output['value']['hop_count'] = max(len(output['value']['chain']) - 1, 0)
        return output

    def get_http_redirect_check(self, domain=None):
        """Whether plain HTTP is upgraded to HTTPS, the chain taken, and HSTS on the final response."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        trace = self.get_server_redirects(domain, '/', scheme='http')['value']
        final_url = trace.get('final_url') or ''
        hsts = None
        resp, err = self._get(domain, '/')
        if not err:
            hsts = resp.headers.get('Strict-Transport-Security')
        output['value'] = {
            'chain': trace.get('chain'),
            'hop_count': trace.get('hop_count'),
            'final_url': final_url or None,
            'upgrades_to_https': final_url.startswith('https://'),
            'served_over_plain_http': bool(final_url) and final_url.startswith('http://'),
            'hsts_header': hsts,
        }
        return output

    def get_favicon_hash(self, domain=None):
        """mmh3 favicon hash with a Shodan search hint."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        favicon_url = self._url(domain, '/favicon.ico')

        try:
            resp = requests.get(favicon_url, headers=self.headers, timeout=self.timeout)
            if resp.status_code != 200 or not resp.content:
                page_resp = requests.get(self._url(domain, '/'), headers=self.headers, timeout=self.timeout)
                icon_match = re.search(
                    r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
                    page_resp.text, re.IGNORECASE
                )
                if icon_match:
                    favicon_url = urllib.parse.urljoin(self._url(domain, '/'), icon_match.group(1))
                    resp = requests.get(favicon_url, headers=self.headers, timeout=self.timeout)
        except requests.RequestException as e:
            output['error'] = str(e)
            return output

        if resp.status_code != 200 or not resp.content:
            output['value'] = {'found': False, 'favicon_url': favicon_url, 'status_code': resp.status_code}
            return output

        sha256 = hashlib.sha256(resp.content).hexdigest()
        try:
            import mmh3
        except ImportError:
            output['value'] = {
                'found': True,
                'favicon_url': favicon_url,
                'status_code': resp.status_code,
                'sha256': sha256,
                'error': "mmh3 package not installed — run `pip install mmh3` to compute the hash",
                'content_length': len(resp.content),
            }
            return output

        b64_content = base64.encodebytes(resp.content)
        favicon_hash = mmh3.hash(b64_content)
        output['value'] = {
            'found': True,
            'favicon_url': favicon_url,
            'status_code': resp.status_code,
            'content_length': len(resp.content),
            'sha256': sha256,
            'mmh3_hash': favicon_hash,
            'shodan_search_hint': f'http.favicon.hash:{favicon_hash}',
        }
        return output

    def get_dns(self, domain=None, nameservers=None, timeout=5, recursion=1, _base_domain=None, _depth=0, _visited=None):
        """A/AAAA/CNAME/MX/NS/TXT plus SPF, DMARC and best-effort DKIM, with recursion into in-scope targets."""
        domain = self._dom(domain)
        if _base_domain is None:
            _base_domain = self._base_domain(domain)
        if _visited is None:
            _visited = set()
        _visited.add(domain)

        output = {
            'domain': domain,
            'time': time.time(),
            'nameservers_used': list(nameservers or self.cfg.settings['nameservers']),
            'value': [],
            'subdomains': {},
        }
        resolver = self._resolver(nameservers, timeout)

        for rtype in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
            output['value'].append(self._dns_query(resolver, domain, rtype))

        txt_result = next((r for r in output['value'] if r['type'] == 'TXT'), None)
        spf_entries = []
        if txt_result and 'entries' in txt_result:
            spf_entries = [e for e in txt_result['entries'] if 'v=spf1' in e['value'].lower()]
        output['value'].append({'type': 'SPF', 'entries': spf_entries})

        dmarc_result = self._dns_query(resolver, f'_dmarc.{domain}', 'TXT')
        output['value'].append({
            'type': 'DMARC',
            'entries': dmarc_result.get('entries', []),
            **({'error': dmarc_result['error']} if 'error' in dmarc_result else {}),
        })

        common_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'dkim', 'mail']
        dkim_entries = []
        for selector in common_selectors:
            result = self._dns_query(resolver, f'{selector}._domainkey.{domain}', 'TXT')
            for entry in result.get('entries', []):
                dkim_entries.append({**entry, 'selector': selector})
        output['value'].append({
            'type': 'DKIM',
            'entries': dkim_entries,
            'selectors_checked': common_selectors,
            'note': 'selector-based probing is best-effort; absence does not confirm DKIM is unconfigured',
        })

        if recursion > 0:
            candidates = set()
            for record in output['value']:
                if record['type'] not in ('CNAME', 'MX', 'NS'):
                    continue
                for entry in record.get('entries', []):
                    val = entry['value'].rstrip('.').lower()
                    if record['type'] == 'MX':
                        val = val.split(' ', 1)[-1]
                    if val.endswith('.' + _base_domain) or val == _base_domain:
                        candidates.add(val)
            candidates -= _visited

            for sub in sorted(candidates):
                if _depth + 1 <= recursion:
                    output['subdomains'][sub] = self.get_dns(
                        sub, nameservers=nameservers, timeout=timeout, recursion=recursion,
                        _base_domain=_base_domain, _depth=_depth + 1, _visited=_visited,
                    )
                else:
                    output['subdomains'][sub] = {'note': 'found but recursion limit reached, not queried'}
        return output

    def _spf_lookups(self, resolver, name, depth=0, visited=None):
        visited = visited if visited is not None else set()
        if depth > 6 or name in visited:
            return 0
        visited.add(name)
        records = [t for t in self._dns_txt(resolver, name) if t.lower().startswith('v=spf1')]
        if not records:
            return 0
        count = 0
        for term in records[0].split()[1:]:
            t = term.lstrip('+-~?').lower()
            if t.startswith('include:'):
                count += 1 + self._spf_lookups(resolver, t.split(':', 1)[1], depth + 1, visited)
            elif t.startswith('redirect='):
                count += 1 + self._spf_lookups(resolver, t.split('=', 1)[1], depth + 1, visited)
            elif re.match(r'(?:a|mx|ptr|exists)(?::|/|$)', t):
                count += 1
        return count

    def _parse_tags(self, record):
        return {
            k.strip().lower(): v.strip()
            for k, _, v in (p.partition('=') for p in record.split(';') if '=' in p)
        }

    def get_email_security(self, domain=None):
        """SPF (strictness, lookup count), DMARC policy, MTA-STS, TLS-RPT, BIMI, MX and DKIM selectors."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        resolver = self._resolver()
        base = self._base_domain(domain)

        mx = self._dns_query(resolver, domain, 'MX')
        mx_hosts = [e['value'] for e in mx.get('entries', [])]
        null_mx = any(h.strip() in ('0 .', '0 ') for h in mx_hosts)

        txts = self._dns_txt(resolver, domain)
        spf_records = [t for t in txts if t.lower().startswith('v=spf1')]
        spf = {'present': bool(spf_records), 'record_count': len(spf_records)}
        if spf_records:
            terms = spf_records[0].split()[1:]
            all_term = next((t for t in terms if re.fullmatch(r'[+\-~?]?all', t.lower())), None)
            policy = {
                '-all': 'fail (strict)', '~all': 'softfail', '?all': 'neutral',
                'all': 'pass (open to everyone)', '+all': 'pass (open to everyone)',
            }.get((all_term or '').lower())
            lookups = self._spf_lookups(resolver, domain)
            spf.update({
                'raw': spf_records[0],
                'all_mechanism': all_term,
                'policy': policy,
                'dns_lookup_count': lookups,
                'exceeds_10_lookup_limit': lookups > 10,
                'multiple_records': len(spf_records) > 1,
            })

        dmarc_name, dmarc_records = f'_dmarc.{domain}', []
        dmarc_records = [t for t in self._dns_txt(resolver, dmarc_name) if t.lower().startswith('v=dmarc1')]
        inherited_from = None
        if not dmarc_records and base != domain:
            dmarc_records = [t for t in self._dns_txt(resolver, f'_dmarc.{base}') if t.lower().startswith('v=dmarc1')]
            inherited_from = base if dmarc_records else None
        dmarc = {'present': bool(dmarc_records)}
        if dmarc_records:
            tags = self._parse_tags(dmarc_records[0])
            dmarc.update({
                'raw': dmarc_records[0],
                'inherited_from': inherited_from,
                'policy': tags.get('p'),
                'subdomain_policy': tags.get('sp'),
                'pct': tags.get('pct'),
                'rua': tags.get('rua'),
                'ruf': tags.get('ruf'),
                'adkim': tags.get('adkim'),
                'aspf': tags.get('aspf'),
            })

        mta_sts = {'present': False}
        sts_txt = [t for t in self._dns_txt(resolver, f'_mta-sts.{domain}') if t.lower().startswith('v=stsv1')]
        if sts_txt:
            mta_sts = {'present': True, 'txt': sts_txt[0]}
            try:
                r = requests.get(f'https://mta-sts.{domain}/.well-known/mta-sts.txt',
                                 headers=self.headers, timeout=6)
                if r.status_code == 200:
                    policy = {}
                    for line in r.text.splitlines():
                        k, _, v = line.partition(':')
                        if v:
                            policy.setdefault(k.strip().lower(), []).append(v.strip())
                    mta_sts['policy'] = {k: (v if k == 'mx' else v[0]) for k, v in policy.items()}
                else:
                    mta_sts['policy_error'] = f'HTTP {r.status_code}'
            except requests.RequestException as e:
                mta_sts['policy_error'] = str(e)

        tls_rpt = [t for t in self._dns_txt(resolver, f'_smtp._tls.{domain}') if t.lower().startswith('v=tlsrptv1')]
        bimi = [t for t in self._dns_txt(resolver, f'default._bimi.{domain}') if t.lower().startswith('v=bimi1')]

        selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'dkim', 'mail',
                     's1', 's2', 'smtp', 'mandrill', 'zoho', 'mxvault', 'everlytickey1']
        dkim = []
        for selector in selectors:
            for t in self._dns_txt(resolver, f'{selector}._domainkey.{domain}'):
                if 'p=' in t.lower():
                    dkim.append({'selector': selector, 'record': t[:200]})

        assessment = []
        if not null_mx and mx_hosts:
            if not spf['present']:
                assessment.append('mail-capable domain without SPF')
            if not dmarc['present']:
                assessment.append('no DMARC record: spoofed mail will not be rejected or reported')
            elif (dmarc.get('policy') or '').lower() == 'none':
                assessment.append('DMARC policy is p=none (monitoring only)')
        elif not mx_hosts and not null_mx:
            if not spf['present'] or spf.get('policy') != 'fail (strict)':
                assessment.append('domain does not receive mail but lacks a null MX / strict SPF to prevent spoofing')

        output['value'] = {
            'mx': {'hosts': mx_hosts, 'null_mx': null_mx},
            'spf': spf,
            'dmarc': dmarc,
            'mta_sts': mta_sts,
            'tls_rpt': {'present': bool(tls_rpt), 'record': tls_rpt[0] if tls_rpt else None},
            'bimi': {'present': bool(bimi), 'record': bimi[0] if bimi else None},
            'dkim': {'selectors_found': dkim, 'selectors_checked': selectors,
                     'note': 'selector probing is best-effort'},
            'assessment': assessment,
        }
        return output

    def get_dns_hardening(self, domain=None):
        """CAA, DNSSEC (DS/DNSKEY), nameserver diversity and wildcard DNS detection."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        resolver = self._resolver()
        base = self._base_domain(domain)

        caa = self._dns_query(resolver, domain, 'CAA')
        caa_at = domain
        if not caa.get('entries') and base != domain:
            caa = self._dns_query(resolver, base, 'CAA')
            caa_at = base
        ds = self._dns_query(resolver, base, 'DS')
        dnskey = self._dns_query(resolver, base, 'DNSKEY')
        ns = self._dns_query(resolver, base, 'NS')
        ns_hosts = [e['value'].rstrip('.').lower() for e in ns.get('entries', [])]
        ns_providers = sorted({self._base_domain(h) for h in ns_hosts})

        wildcard = self._dns_query(resolver, f'webspy-{secrets.token_hex(6)}.{domain}', 'A')

        output['value'] = {
            'caa': {
                'present': bool(caa.get('entries')),
                'queried_at': caa_at,
                'records': [e['value'] for e in caa.get('entries', [])],
            },
            'dnssec': {
                'ds_present': bool(ds.get('entries')),
                'dnskey_present': bool(dnskey.get('entries')),
                'enabled': bool(ds.get('entries')),
            },
            'nameservers': {
                'hosts': ns_hosts,
                'count': len(ns_hosts),
                'provider_domains': ns_providers,
                'single_provider': len(ns_providers) == 1,
            },
            'wildcard_dns': {
                'detected': bool(wildcard.get('entries')),
                'answers': [e['value'] for e in wildcard.get('entries', [])],
            },
        }
        return output

    def _cymru_lookup(self, resolver, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 4:
            name = '.'.join(reversed(ip.split('.'))) + '.origin.asn.cymru.com'
        else:
            name = '.'.join(reversed(addr.exploded.replace(':', ''))) + '.origin6.asn.cymru.com'
        txt = self._dns_txt(resolver, name)
        if not txt:
            return None
        fields = [f.strip() for f in txt[0].split('|')]
        if len(fields) < 5:
            return None
        asn = fields[0].split()[0]
        info = {'asn': f'AS{asn}', 'prefix': fields[1], 'country': fields[2],
                'registry': fields[3], 'allocated': fields[4], 'as_name': None}
        name_txt = self._dns_txt(resolver, f'AS{asn}.asn.cymru.com')
        if name_txt:
            parts = [p.strip() for p in name_txt[0].split('|')]
            if len(parts) >= 5:
                info['as_name'] = parts[4]
        return info

    def get_ip_intel(self, domain=None):
        """Resolved IPs with reverse DNS, ASN, prefix, country and registry (Team Cymru DNS)."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {'ips': []}}
        resolver = self._resolver()
        ips = []
        for rtype in ('A', 'AAAA'):
            ips += [e['value'] for e in self._dns_query(resolver, domain, rtype).get('entries', [])]

        for ip in ips:
            entry = {'ip': ip}
            try:
                entry['is_private'] = ipaddress.ip_address(ip).is_private
            except ValueError:
                entry['is_private'] = None
            try:
                ptr = resolver.resolve(dns.reversename.from_address(ip), 'PTR')
                entry['reverse_dns'] = [r.to_text().rstrip('.') for r in ptr]
            except Exception:
                entry['reverse_dns'] = []
            entry['network'] = self._cymru_lookup(resolver, ip)
            output['value']['ips'].append(entry)

        asns = sorted({e['network']['asn'] for e in output['value']['ips'] if e.get('network')})
        output['summary'] = {'ip_count': len(ips), 'asns': asns}
        return output

    def get_rdap(self, domain=None):
        """Registration data via RDAP: registrar, creation/expiry/update dates, status, nameservers, domain age."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        base = self._base_domain(domain)
        try:
            resp = requests.get(
                f'https://rdap.org/domain/{base}',
                headers={'User-Agent': self.ua, 'Accept': 'application/rdap+json'},
                timeout=15,
            )
        except requests.RequestException as e:
            output['error'] = str(e)
            return output
        if resp.status_code != 200:
            output['value'] = {'available': False, 'status_code': resp.status_code,
                               'note': 'no RDAP service reachable for this TLD via rdap.org'}
            return output
        try:
            data = resp.json()
        except ValueError:
            output['error'] = 'RDAP response was not JSON'
            return output

        def parse_date(value):
            try:
                return datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                return None

        events = {}
        for ev in data.get('events', []):
            events[ev.get('eventAction')] = ev.get('eventDate')

        registrar = None
        for ent in data.get('entities', []):
            if 'registrar' in (ent.get('roles') or []):
                vcard = (ent.get('vcardArray') or [None, []])[1]
                for item in vcard:
                    if item and item[0] == 'fn':
                        registrar = item[3]
                        break
                break

        now = datetime.datetime.now(datetime.timezone.utc)
        created = parse_date(events.get('registration'))
        expires = parse_date(events.get('expiration'))
        output['value'] = {
            'available': True,
            'queried_domain': base,
            'registrar': registrar,
            'status': data.get('status', []),
            'registered': events.get('registration'),
            'expires': events.get('expiration'),
            'last_changed': events.get('last changed'),
            'nameservers': [n.get('ldhName') for n in data.get('nameservers', []) if n.get('ldhName')],
            'dnssec_signed': (data.get('secureDNS') or {}).get('delegationSigned'),
            'domain_age_days': (now - created).days if created and created.tzinfo else None,
            'days_until_expiry': (expires - now).days if expires and expires.tzinfo else None,
        }
        return output

    def get_whois(self, domain=None):
        """Raw WHOIS lookup via the IANA referral chain — a fallback for TLDs with no RDAP service."""
        domain = self._dom(domain)
        base = self._base_domain(domain)
        output = {'domain': base, 'time': time.time(), 'value': {}}
        server = 'whois.iana.org'
        seen_servers = []
        text = ''
        try:
            for _ in range(4):
                seen_servers.append(server)
                text = self._whois_query(server, base)
                m = _WHOIS_REFERRAL_RE.search(text)
                if m and m.group(1).lower() != server.lower():
                    server = m.group(1).lower()
                    continue
                break
        except (socket.timeout, OSError, ConnectionRefusedError) as e:
            output['error'] = str(e)
            return output

        output['value'] = {
            'servers_queried': seen_servers,
            'raw': text[:8000],
            'truncated': len(text) > 8000,
        }
        return output

    def get_wayback(self, domain=None):
        """Internet Archive history: first/last capture and years with a successful snapshot."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        cdx = 'https://web.archive.org/cdx/search/cdx'

        def query(params):
            resp = requests.get(cdx, params=params, headers=self.headers, timeout=25)
            resp.raise_for_status()
            if not resp.text.strip():
                return []
            rows = resp.json()
            return rows[1:] if rows else []

        try:
            yearly = query({'url': domain, 'output': 'json', 'fl': 'timestamp,statuscode',
                            'collapse': 'timestamp:4', 'filter': 'statuscode:200', 'limit': 60})
            latest = query({'url': domain, 'output': 'json', 'fl': 'timestamp,statuscode', 'limit': -1})
        except (requests.RequestException, ValueError) as e:
            output['error'] = str(e)
            return output

        def fmt(ts):
            return f'{ts[0:4]}-{ts[4:6]}-{ts[6:8]}' if ts and len(ts) >= 8 else ts

        output['value'] = {
            'has_snapshots': bool(yearly or latest),
            'first_successful_capture': fmt(yearly[0][0]) if yearly else None,
            'latest_capture': fmt(latest[0][0]) if latest else None,
            'years_with_snapshots': sorted({r[0][:4] for r in yearly}),
            'archive_url': f'https://web.archive.org/web/*/{domain}',
        }
        return output

    def get_mime_handling(self, domain=None, endpoints=None):
        """Declared Content-Type vs sniffed content, and nosniff presence."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        signatures = self.cfg.http_checks.mime_signatures

        def _sniff(content_bytes):
            head = content_bytes[:32]
            for sig, mime in signatures:
                if head.startswith(sig):
                    return mime
            sample = content_bytes[:512].lstrip()
            lower_sample = sample.lower()
            if lower_sample.startswith(b'<!doctype html') or lower_sample.startswith(b'<html'):
                return 'text/html'
            if sample.startswith(b'<?php'):
                return 'text/x-php (should never be served as-is)'
            if sample[:1] in (b'{', b'['):
                try:
                    json.loads(content_bytes.decode('utf-8', errors='ignore'))
                    return 'application/json'
                except (ValueError, json.JSONDecodeError):
                    pass
            return None

        def _family(mime):
            if not mime:
                return None
            base = mime.split(';')[0].strip().lower()
            if base.startswith('image/'):
                return 'image'
            if base in ('text/html', 'application/xhtml+xml'):
                return 'html'
            if base in ('application/json', 'text/json'):
                return 'json'
            if base in ('application/zip', 'application/x-zip-compressed'):
                return 'zip'
            if base == 'application/pdf':
                return 'pdf'
            if base in ('application/xml', 'text/xml'):
                return 'xml'
            return base

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue

            declared_type = resp.headers.get('Content-Type', '')
            nosniff_header = resp.headers.get('X-Content-Type-Options', '')
            nosniff_present = nosniff_header.lower() == 'nosniff'
            sniffed_type = _sniff(resp.content)
            mismatch = (
                _family(sniffed_type) is not None
                and _family(declared_type) is not None
                and _family(sniffed_type) != _family(declared_type)
            )

            output['value'][endpoint] = {
                'status_code': resp.status_code,
                'declared_content_type': declared_type,
                'sniffed_content_type': sniffed_type,
                'mismatch': mismatch,
                'x_content_type_options': nosniff_header or None,
                'nosniff_present': nosniff_present,
                'sniffing_risk': mismatch and not nosniff_present,
            }
        return output

    def get_http_versions(self, domain=None, port=443):
        """HTTP/1.1 reachability, HTTP/2 via ALPN and HTTP/3 advertisement via Alt-Svc."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        resp, err = self._get(domain, '/')
        if err:
            output['value']['http1_1'] = {'supported': False, 'error': err}
            alt_svc = None
        else:
            output['value']['http1_1'] = {'supported': True, 'status_code': resp.status_code}
            alt_svc = resp.headers.get('Alt-Svc')

        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    negotiated = ssock.selected_alpn_protocol()
            output['value']['http2'] = {'supported': negotiated == 'h2', 'alpn_negotiated': negotiated}
        except Exception as e:
            output['value']['http2'] = {'supported': False, 'error': str(e)}

        h3_advertised = bool(alt_svc and re.search(r'h3(-\d+)?=', alt_svc))
        output['value']['http3_quic'] = {
            'advertised': h3_advertised,
            'alt_svc_header': alt_svc,
            'note': 'advertised via Alt-Svc only — not a confirmed QUIC handshake',
        }
        return output

    def get_cdn_detection(self, domain=None):
        """CDN/proxy identification from headers, CNAME chain and certificate issuer."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {'findings': [], 'raw_signals': {}}}
        findings = output['value']['findings']

        def add(cdn, confidence, reason):
            findings.append({'cdn': cdn, 'confidence': confidence, 'evidence': reason})

        resp, err = self._get(domain, '/')
        headers = resp.headers if resp else {}
        if err:
            output['value']['raw_signals']['headers_error'] = err
        else:
            output['value']['raw_signals']['headers'] = dict(headers)

        header_keys_lower = {k.lower(): v for k, v in headers.items()}
        for header_name, vendor in self.cfg.edge_vendors.headers:
            if header_name in header_keys_lower:
                add(vendor, 'high', f"{header_name}: {header_keys_lower[header_name]}")

        server = (headers.get('Server') or '').lower()
        for needle, vendor in self.cfg.edge_vendors.server_checks:
            if needle in server:
                add(vendor, 'high', f"Server header: {headers.get('Server')}")

        try:
            resolver = self._resolver()
            answer = resolver.resolve(domain, 'CNAME')
            cname_chain = [r.to_text().rstrip('.').lower() for r in answer]
            output['value']['raw_signals']['cname_chain'] = cname_chain
            for cname in cname_chain:
                for rx, cdn in self.cfg.edge_vendors.cnames:
                    if rx.search(cname):
                        add(cdn, 'high', f"CNAME chain: {cname}")
        except dns.resolver.NoAnswer:
            output['value']['raw_signals']['cname_chain'] = []
        except Exception as e:
            output['value']['raw_signals']['cname_error'] = str(e)

        try:
            cert, *_ = self._tls_handshake(domain)
            issuer = dict(x[0] for x in cert.get('issuer', []))
            issuer_org = (issuer.get('organizationName') or '').lower()
            output['value']['raw_signals']['cert_issuer'] = issuer
            for pattern, cdn in self.cfg.edge_vendors.cert_issuer_checks:
                if pattern in issuer_org:
                    add(cdn, 'medium', f"TLS cert issuer org: {issuer.get('organizationName')}")
        except Exception as e:
            output['value']['raw_signals']['cert_error'] = str(e)

        output['value']['findings'] = self._dedup_findings(findings, 'cdn')
        return output

    def get_graphql_introspection(self, domain=None, endpoints=None):
        """Whether GraphQL endpoints answer an introspection query."""
        domain = self._dom(domain)
        if endpoints is None:
            endpoints = list(self.cfg.graphql.graphql_endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        introspection_query = self.cfg.graphql.introspection_query

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint, method='POST', json=introspection_query)
            if err:
                output['value'][endpoint] = {'error': err}
                continue
            try:
                data = resp.json()
            except (ValueError, json.JSONDecodeError):
                output['value'][endpoint] = {
                    'status_code': resp.status_code,
                    'introspection_enabled': False,
                    'note': 'response was not JSON',
                }
                continue

            schema = data.get('data', {}).get('__schema') if isinstance(data, dict) and isinstance(data.get('data'), dict) else None
            if schema:
                type_names = [t['name'] for t in schema.get('types', []) if t.get('name')]
                output['value'][endpoint] = {
                    'status_code': resp.status_code,
                    'introspection_enabled': True,
                    'query_type': (schema.get('queryType') or {}).get('name'),
                    'mutation_type': (schema.get('mutationType') or {}).get('name'),
                    'type_count': len(type_names),
                    'type_names_sample': type_names[:25],
                    'risk': 'Introspection exposes the full schema — should generally be disabled in production.',
                }
            else:
                output['value'][endpoint] = {
                    'status_code': resp.status_code,
                    'introspection_enabled': False,
                    'errors': data.get('errors') if isinstance(data, dict) else None,
                }
        return output

    def get_api_discovery(self, domain=None):
        """Common OpenAPI/Swagger/GraphQL/actuator paths, filtered against the site's soft-404 behaviour."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        baseline = self._baseline(domain)
        found = {}
        for path in self.cfg.exposure.api_docs:
            resp, err = self._get(domain, path)
            if err or resp.status_code >= 400:
                continue
            if baseline and hashlib.sha1(resp.content).hexdigest() == baseline['sha1']:
                continue
            entry = {'status_code': resp.status_code}
            content_type = resp.headers.get('Content-Type', '')
            if 'json' in content_type:
                entry['looks_like_api_spec'] = any(
                    key in resp.text.lower() for key in ('"openapi"', '"swagger"', '"paths"')
                )
            found[path] = entry
        output['value'] = found
        output['summary'] = {
            'candidates_checked': len(self.cfg.exposure.api_docs),
            'found_count': len(found),
            'soft_404_baseline': baseline['status_code'] if baseline else None,
        }
        return output

    def get_js_file_analysis(self, domain=None, endpoints=None, max_files=25):
        """Linked JS files scanned for secrets (masked) and exposed source maps."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        def mask(value):
            return value if len(value) <= 8 else value[:4] + '…' + value[-2:]

        for endpoint in endpoints:
            page_resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue

            seen, js_urls = set(), []
            for asset in _parse_assets(page_resp.text or '', page_resp.url):
                if asset['kind'] == 'script' and asset['attr'] == 'src' and asset['url'] not in seen:
                    seen.add(asset['url'])
                    js_urls.append(asset['url'])

            files = []
            for js_url in js_urls[:max_files]:
                try:
                    resp = requests.get(js_url, headers=self.headers, timeout=self.timeout)
                except requests.RequestException as e:
                    files.append({'file': js_url, 'error': str(e)})
                    continue

                body = resp.text or ''
                findings = []
                for rx, label in self.cfg.secrets.patterns:
                    matches = [m.group(0) for m in rx.finditer(body)]
                    if matches:
                        findings.append({'type': label, 'match_count': len(matches), 'sample_masked': mask(matches[0])})

                source_map_comment = re.search(r'//#\s*sourceMappingURL=(\S+)', body)
                source_map_url = None
                source_map_accessible = False
                if source_map_comment:
                    source_map_url = urllib.parse.urljoin(js_url, source_map_comment.group(1))
                else:
                    guess = js_url + '.map'
                    try:
                        if requests.head(guess, headers=self.headers, timeout=5).status_code == 200:
                            source_map_url = guess
                    except requests.RequestException:
                        pass

                if source_map_url:
                    try:
                        source_map_accessible = requests.head(source_map_url, headers=self.headers, timeout=5).status_code == 200
                    except requests.RequestException:
                        pass

                files.append({
                    'file': js_url,
                    'status_code': resp.status_code,
                    'size_bytes': len(resp.content),
                    'secrets_found': findings,
                    'source_map_url': source_map_url,
                    'source_map_accessible': source_map_accessible,
                })
            output['value'][endpoint] = files
        return output

    def get_comments_metadata(self, domain=None, endpoints=None):
        """HTML comments and meta tags, flagging leaks such as internal IPs, emails and developer notes."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        flag_patterns = self.cfg.content_checks.comment_flags

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue
            body = resp.text or ''

            comments = [c.strip() for c in re.findall(r'<!--(.*?)-->', body, re.DOTALL) if c.strip()]
            meta_tags = {}
            for match in re.finditer(r'<meta\s+([^>]+)>', body, re.IGNORECASE):
                attrs_str = match.group(1)
                name_match = re.search(r'name=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
                content_match = re.search(r'content=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
                if name_match and content_match:
                    meta_tags[name_match.group(1)] = content_match.group(1)

            flagged = []
            for comment in comments:
                for rx, reason in flag_patterns:
                    if rx.search(comment):
                        flagged.append({'source': 'comment', 'content': comment[:200], 'reason': reason})
                        break
            for name, content in meta_tags.items():
                if name.lower() == 'generator':
                    flagged.append({'source': 'meta', 'name': name, 'content': content, 'reason': 'reveals CMS/framework and often version'})

            output['value'][endpoint] = {
                'comments': comments[:100],
                'meta_tags': meta_tags,
                'flagged': flagged,
            }
        return output

    def get_error_page_fingerprint(self, domain=None):
        """Default error page of a guaranteed-missing path, to reveal stack, framework and debug exposure."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        probe_path = '/webspy-probe-' + str(int(time.time())) + '-nonexistent'

        resp, err = self._get(domain, probe_path)
        if err:
            output['error'] = err
            return output
        body = resp.text or ''

        matched = [label for rx, label in self.cfg.error_pages.fingerprints if rx.search(body)]

        output['value'] = {
            'probe_path': probe_path,
            'status_code': resp.status_code,
            'server_header': resp.headers.get('Server'),
            'x_powered_by': resp.headers.get('X-Powered-By'),
            'body_length': len(body),
            'fingerprints_matched': matched,
            'stack_trace_exposed': any(k in m.lower() for m in matched for k in ('stack trace', 'debug', 'misconfig', 'serious')),
            'takeover_risk': any('takeover risk' in m.lower() for m in matched),
        }
        return output

    def get_exposed_files(self, domain=None, workers=8):
        """Existence checks for sensitive files, validated by content and filtered against soft-404 pages."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        baseline = self._baseline(domain)
        baseline_soft = bool(baseline and baseline['status_code'] == 200)

        def probe(path):
            try:
                resp = requests.get(
                    self._url(domain, path), headers=self.headers,
                    timeout=self.timeout, allow_redirects=False, stream=True,
                )
            except requests.RequestException:
                return path, None
            try:
                chunk = next(resp.iter_content(4096), b'')
                return path, (resp.status_code, dict(resp.headers), chunk)
            except requests.RequestException:
                return path, None
            finally:
                resp.close()

        found = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for path, result in pool.map(probe, self.cfg.exposure.exposed_files):
                if not result:
                    continue
                status, headers, chunk = result
                if status != 200 or not chunk:
                    continue
                ctype = (headers.get('Content-Type') or '').lower()
                validator = self.cfg.validators.by_path.get(path)
                validated = None if validator is None else bool(validator.search(chunk.decode('utf-8', 'replace')))
                if validated is False:
                    continue
                if baseline_soft and validated is not True:
                    continue
                if validated is None and 'html' in ctype:
                    continue
                length = headers.get('Content-Length')
                found[path] = {
                    'status_code': status,
                    'content_length': int(length) if length and length.isdigit() else None,
                    'content_type': headers.get('Content-Type'),
                    'content_validated': validated,
                }
        output['value'] = found
        output['summary'] = {
            'candidates_checked': len(self.cfg.exposure.exposed_files),
            'exposed_count': len(found),
            'soft_404_site': baseline_soft,
        }
        return output

    def get_open_directory_listing(self, domain=None, paths=None):
        """Checks common directory paths for autoindex ("Index of /") listings that expose file and folder names."""
        domain = self._dom(domain)
        paths = list(paths) if paths else COMMON_LISTABLE_PATHS
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        found = {}
        for path in paths:
            resp, err = self._get(domain, path)
            if err or resp.status_code != 200:
                continue
            body = resp.text or ''
            if _DIR_LISTING_RE.search(body):
                links = [u for u in re.findall(r'href=["\']([^"\']+)["\']', body)
                         if u not in ('../', '/') and not u.startswith('?')]
                found[path] = {
                    'status_code': resp.status_code,
                    'entry_count_guess': len(links),
                    'sample_entries': links[:25],
                }
        output['value'] = found
        output['summary'] = {'paths_checked': len(paths), 'listing_found_count': len(found)}
        return output

    def get_port_scan(self, domain=None, ports=None, timeout=1.5, workers=100, grab_banners=True):
        """TCP connect scan (full handshake, not a raw SYN scan) of common ports, to see what other services share the host(s) behind this domain. Only run against hosts you are authorized to test."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        resolver = self._resolver()
        ips = []
        for rtype in ('A', 'AAAA'):
            ips += [e['value'] for e in self._dns_query(resolver, domain, rtype).get('entries', [])]
        if not ips:
            output['error'] = 'could not resolve domain to an IP address'
            return output

        port_list = sorted(set(ports)) if ports else sorted(COMMON_SCAN_PORTS)
        tls_like = {'https', 'https-alt', 'smtps', 'imaps', 'pop3s'}

        def scan_one(args):
            ip, port = args
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    pass
            except (socket.timeout, ConnectionRefusedError, OSError):
                return None
            service = COMMON_SCAN_PORTS.get(port, 'unknown')
            banner = None
            if grab_banners:
                banner = self._grab_banner(ip, port, timeout, use_tls=service in tls_like)
            return {'port': port, 'service': service, 'banner': banner}

        tasks = [(ip, port) for ip in ips for port in port_list]
        results_by_ip = {ip: [] for ip in ips}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for (ip, _port), res in zip(tasks, pool.map(scan_one, tasks)):
                if res:
                    results_by_ip[ip].append(res)
        for ip in results_by_ip:
            results_by_ip[ip].sort(key=lambda r: r['port'])

        output['value'] = {
            'resolved_ips': ips,
            'ports_checked': len(port_list),
            'open_ports': results_by_ip,
        }
        output['summary'] = {
            'total_open': sum(len(v) for v in results_by_ip.values()),
            'note': ('TCP connect scan only (full handshake). For a true half-open SYN scan — e.g. to '
                     'sweep a very large port range with a smaller logging footprint — use a dedicated '
                     'tool such as nmap -sS with appropriate privileges, against hosts you are authorized to test.'),
        }
        return output

    def get_sri_usage(self, domain=None, endpoints=None):
        """Subresource Integrity coverage for third-party scripts and stylesheets."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue

            resources = []
            for asset in _parse_assets(resp.text or '', resp.url):
                if asset['attr'] not in ('src', 'href'):
                    continue
                is_script = asset['kind'] == 'script'
                is_css = asset['kind'] == 'link' and 'stylesheet' in (asset['attrs'].get('rel') or '').lower()
                if not (is_script or is_css):
                    continue
                if not self._is_third_party(asset['host'], domain):
                    continue
                has_integrity = bool(asset['attrs'].get('integrity'))
                resources.append({
                    'tag': 'script' if is_script else 'link',
                    'resource': asset['url'],
                    'host': asset['host'],
                    'has_integrity': has_integrity,
                    'has_crossorigin': bool(re.search(r'\bcrossorigin\b', asset['raw_attrs'], re.I)),
                    'risk': not has_integrity,
                })

            output['value'][endpoint] = {
                'resources': resources,
                'summary': {
                    'external_resources_checked': len(resources),
                    'missing_sri_count': sum(1 for r in resources if r['risk']),
                },
            }
        return output

    # -- Certificate Transparency -------------------------------------------------------------
    # crt.sh is a free public service that frequently answers with 502/503/504 or times out, so
    # lookups retry with backoff and fall back to a second CT index (Cert Spotter).

    def _ct_from_crtsh(self, domain):
        """Rows of (name, issuer, not_before, not_after) from crt.sh, or (None, error)."""
        # '%.domain' matches the apex's subdomains; the apex itself is added by a second query
        # only if the first returns nothing (keeps the load on crt.sh low).
        data, err = self._get_json_retry('https://crt.sh/', params={'q': f'%.{domain}', 'output': 'json'},
                                         timeout=35, attempts=3, backoff=3.0)
        if err:
            return None, f'crt.sh: {err}'
        rows = []
        for rec in data or []:
            if not isinstance(rec, dict):
                continue
            for name in str(rec.get('name_value', '')).split('\n'):
                rows.append((name, rec.get('issuer_name'), rec.get('not_before'), rec.get('not_after')))
        return rows, None

    def _ct_from_certspotter(self, domain, max_pages=5):
        """Rows of (name, issuer, not_before, not_after) from Cert Spotter's public API, or (None, error)."""
        rows, after = [], None
        for page in range(max_pages):
            params = {'domain': domain, 'include_subdomains': 'true', 'expand': ['dns_names', 'issuer']}
            if after:
                params['after'] = after
            data, err = self._get_json_retry('https://api.certspotter.com/v1/issuances', params=params,
                                             timeout=30, attempts=2, backoff=3.0)
            if err:
                if rows:
                    break                      # keep what earlier pages returned
                return None, f'certspotter: {err}'
            if not isinstance(data, list) or not data:
                break
            for rec in data:
                if not isinstance(rec, dict):
                    continue
                issuer = (rec.get('issuer') or {}).get('friendly_name') or (rec.get('issuer') or {}).get('name')
                for name in rec.get('dns_names') or []:
                    rows.append((name, issuer, rec.get('not_before'), rec.get('not_after')))
                after = rec.get('id') or after
            if len(data) < 100:
                break
        return rows, None

    def _ct_collect(self, domain):
        """Query CT sources in order until one answers. Returns (entries, source, errors)."""
        errors = []
        for source, fetch in (('crt.sh', self._ct_from_crtsh), ('certspotter', self._ct_from_certspotter)):
            rows, err = fetch(domain)
            if err:
                errors.append(err)
                continue
            seen, entries = set(), []
            for raw_name, issuer, not_before, not_after in rows:
                name = (raw_name or '').strip().lower().rstrip('.')
                wildcard = name.startswith('*.')
                name = name[2:] if wildcard else name
                if not name or '@' in name or ' ' in name:
                    continue
                if name != domain and not name.endswith('.' + domain):
                    continue                    # SAN belonging to an unrelated domain
                if name in seen:
                    continue
                seen.add(name)
                entries.append({
                    'subdomain': name,
                    'wildcard': wildcard,
                    'issuer': issuer,
                    'not_before': not_before,
                    'not_after': not_after,
                })
            if entries or source == 'certspotter':
                return sorted(entries, key=lambda e: e['subdomain']), source, errors
            errors.append(f'{source}: answered but returned no names for {domain}')
        return [], None, errors

    def get_cert_transparency(self, domain=None):
        """Subdomain and certificate history from Certificate Transparency logs (crt.sh, with Cert Spotter fallback)."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': []}

        with self._ct_lock:                     # one lookup at a time; parallel probes reuse the result
            cached = self._ct_cache.get(domain)
            ttl = self.cache_ttl if cached and cached['ok'] else CT_FAILURE_TTL
            if cached and time.time() - cached['at'] < max(ttl, CT_FAILURE_TTL):
                result = cached
            else:
                entries, source, errors = self._ct_collect(domain)
                result = {'at': time.time(), 'ok': source is not None,
                          'entries': entries, 'source': source, 'errors': errors}
                self._ct_cache[domain] = result

        if not result['ok']:
            output['error'] = 'all Certificate Transparency sources failed: ' + '; '.join(result['errors'])
            return output

        output['value'] = result['entries']
        output['summary'] = {
            'unique_names_found': len(result['entries']),
            'source': result['source'],
            'fallback_used': result['source'] != 'crt.sh',
            'source_errors': result['errors'],
        }
        return output

    def get_subdomain_bruteforce(self, domain=None, wordlist=None, workers=50, timeout=4):
        """Resolve a wordlist of common subdomain labels, to find names that never appeared in a TLS certificate and so are invisible to Certificate Transparency enumeration."""
        domain = self._dom(domain)
        base = self._base_domain(domain)
        words = list(wordlist) if wordlist else COMMON_SUBDOMAINS
        output = {'domain': base, 'time': time.time(), 'value': {}}

        def resolve_one(word):
            name = f'{word}.{base}'
            resolver = self._resolver(timeout=timeout)
            found = {}
            for rtype in ('A', 'AAAA', 'CNAME'):
                result = self._dns_query(resolver, name, rtype)
                if result.get('entries'):
                    found[rtype] = [e['value'] for e in result['entries']]
            return (name, found) if found else None

        found = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(resolve_one, words):
                if result:
                    found[result[0]] = result[1]

        output['value'] = found
        output['summary'] = {'words_checked': len(words), 'found_count': len(found)}
        return output

    def get_takeover_candidates(self, domain=None, subdomains=None, max_hosts=150, workers=10):
        """Dangling CNAMEs and unclaimed third-party services among subdomains (from CT logs unless supplied; falls back to DNS-linked names if CT is unavailable)."""
        domain = self._dom(domain)
        output = {'domain': domain, 'time': time.time(), 'value': {}}
        warnings = []
        subdomain_source = 'supplied'

        if subdomains is None:
            ct = self.get_cert_transparency(domain)
            if 'error' in ct:
                # Degrade gracefully: use the apex, www and any in-scope hosts the domain's own
                # DNS records point at, so the check still runs instead of failing outright.
                warnings.append(f'Certificate Transparency unavailable ({ct["error"]}); '
                                'checked only the apex, www and names referenced by its DNS records')
                subdomain_source = 'dns_fallback'
                subdomains = [domain, f'www.{domain}']
                try:
                    subdomains += list(self.get_dns(domain, recursion=1).get('subdomains', {}))
                except Exception as e:
                    warnings.append(f'DNS fallback enumeration failed: {type(e).__name__}: {e}')
            else:
                subdomain_source = ct['summary']['source']
                subdomains = [e['subdomain'] for e in ct['value']]

        suffix = domain.lower()
        names = sorted({
            s.lower().strip().lstrip('*.') for s in subdomains
            if '@' not in s and (s.lower().lstrip('*.') == suffix or s.lower().endswith('.' + suffix))
        })[:max_hosts]

        def http_body(host):
            for scheme in ('https', 'http'):
                try:
                    r = requests.get(f'{scheme}://{host}/', headers=self.headers, timeout=6)
                    return r.text[:20000]
                except requests.RequestException:
                    continue
            return None

        def check(name):
            resolver = self._resolver(timeout=4)
            chain, current = [], name
            for _ in range(8):
                try:
                    answer = resolver.resolve(current, 'CNAME')
                except Exception:
                    break
                current = answer[0].target.to_text().rstrip('.').lower()
                chain.append(current)
            if not chain:
                return None

            final = chain[-1]
            resolves = True
            try:
                resolver.resolve(final, 'A')
            except dns.resolver.NXDOMAIN:
                resolves = False
            except Exception:
                resolves = True

            service, fingerprint = None, None
            for rx, svc, fp in self.cfg.takeover.signatures:
                if rx.search(final):
                    service, fingerprint = svc, fp
                    break

            fingerprint_matched = None
            if resolves and service and fingerprint:
                body = http_body(name)
                fingerprint_matched = bool(body and fingerprint.search(body))

            if not resolves and service:
                risk, reason = 'high', f'CNAME points to non-existent {service} resource'
            elif not resolves:
                risk, reason = 'medium', 'CNAME target does not resolve (dangling)'
            elif fingerprint_matched:
                risk, reason = 'high', f'{service} reports the resource is unclaimed'
            elif service:
                risk, reason = 'info', f'points to {service}; no takeover fingerprint seen'
            else:
                return None

            return {
                'subdomain': name,
                'cname_chain': chain,
                'final_target': final,
                'target_resolves': resolves,
                'service': service,
                'fingerprint_matched': fingerprint_matched,
                'risk': risk,
                'reason': reason,
            }

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for r in pool.map(check, names):
                if r:
                    results.append(r)

        results.sort(key=lambda r: -self.severity_rank[r['risk']])
        output['value'] = {
            'candidates': [r for r in results if r['risk'] in ('high', 'medium')],
            'third_party_cnames': [r for r in results if r['risk'] == 'info'],
        }
        output['summary'] = {
            'subdomains_checked': len(names),
            'candidate_count': len(output['value']['candidates']),
            'subdomain_source': subdomain_source,
            'warnings': warnings,
        }
        return output

    def get_rate_limit_headers(self, domain=None, endpoints=None):
        """X-RateLimit-*, RateLimit-* and Retry-After headers."""
        domain = self._dom(domain)
        endpoints = self._endpoints(endpoints)
        output = {'domain': domain, 'time': time.time(), 'value': {}}

        rate_limit_headers = self.cfg.http_checks.rate_limit_headers

        for endpoint in endpoints:
            resp, err = self._get(domain, endpoint)
            if err:
                output['value'][endpoint] = {'error': err}
                continue
            found = {h: resp.headers.get(h) for h in rate_limit_headers if resp.headers.get(h) is not None}
            output['value'][endpoint] = {
                'status_code': resp.status_code,
                'headers_found': found,
                'rate_limiter_signaled': bool(found),
            }
        return output

    def list_probes(self):
        """Names and one-line descriptions of every available probe."""
        return [
            (name, (inspect.getdoc(fn) or '').split('\n')[0])
            for name, fn in inspect.getmembers(type(self), inspect.isfunction)
            if name.startswith('get_')
        ]

    def _run_probe(self, name, domain, endpoints=None):
        fn = getattr(self, name, None) if name.startswith('get_') else None
        if fn is None or not callable(fn):
            return {'domain': domain, 'time': time.time(), 'error': f'unknown probe: {name}'}
        kwargs = {}
        if endpoints and 'endpoints' in inspect.signature(fn).parameters:
            kwargs['endpoints'] = endpoints
        try:
            return fn(domain, **kwargs)
        except Exception as e:
            return {'domain': domain, 'time': time.time(), 'error': f'{type(e).__name__}: {e}'}

    def derive_findings(self, results):
        """Turn probe outputs into severity-ranked audit findings."""
        findings = []
        http_cfg = self.cfg.http_checks

        def add(severity, category, title, detail='', source=''):
            findings.append({
                'severity': severity, 'category': category,
                'title': title, 'detail': detail, 'source': source,
            })

        def entries(name):
            value = (results.get(name) or {}).get('value')
            if isinstance(value, dict):
                for endpoint, entry in value.items():
                    if isinstance(entry, dict) and 'error' not in entry:
                        yield endpoint, entry

        def value_of(name):
            out = results.get(name) or {}
            value = out.get('value')
            return value if isinstance(value, dict) and 'error' not in value else None

        header_rules = {
            'Strict-Transport-Security': ('medium', 'HSTS header missing', 'Browsers are not instructed to enforce HTTPS.'),
            'Content-Security-Policy': ('medium', 'Content-Security-Policy missing', 'No CSP to limit script and frame sources.'),
            'X-Frame-Options': ('low', 'Clickjacking protection missing', 'Neither X-Frame-Options nor CSP frame-ancestors is set.'),
            'X-Content-Type-Options': ('low', 'X-Content-Type-Options missing', 'MIME sniffing is not disabled.'),
            'Referrer-Policy': ('low', 'Referrer-Policy missing', 'Full URLs may leak via the Referer header.'),
            'Permissions-Policy': ('info', 'Permissions-Policy missing', 'Browser feature access is not restricted.'),
        }
        for ep, entry in entries('get_security'):
            csp_val = ((entry.get('Content-Security-Policy') or {}).get('value') or '').lower()
            for header, (sev, title, detail) in header_rules.items():
                info = entry.get(header)
                if info and not info.get('present'):
                    if header == 'X-Frame-Options' and 'frame-ancestors' in csp_val:
                        continue
                    add(sev, 'headers', f'{title} ({ep})', detail, 'get_security')

        for ep, entry in entries('get_csp_policy'):
            if entry.get('present') and entry.get('flags'):
                add('low', 'headers', f'Weak CSP directives ({ep})', '; '.join(entry['flags']), 'get_csp_policy')
            if entry.get('present') and entry.get('report_only'):
                add('info', 'headers', f'CSP is report-only ({ep})', 'Policy is not enforced.', 'get_csp_policy')

        tls = results.get('get_tls_info') or {}
        tls_value = tls.get('value') or {}
        if tls_value.get('error'):
            add('high', 'tls', 'TLS handshake or certificate validation failed', tls_value['error'], 'get_tls_info')
        elif tls_value:
            days = tls_value.get('days_remaining')
            tls_cfg = http_cfg.tls_checks
            warn_days = tls_cfg['flag_cert_days_remaining_below']
            urgent_days = min(14, warn_days)
            if tls_value.get('expired'):
                add('critical', 'tls', 'Certificate has expired', f"expired {abs(days)} days ago", 'get_tls_info')
            elif days is not None and days < urgent_days:
                add('high', 'tls', f'Certificate expires within {urgent_days} days', f'{days} days remaining', 'get_tls_info')
            elif days is not None and days < warn_days:
                add('medium', 'tls', f'Certificate expires within {warn_days} days', f'{days} days remaining', 'get_tls_info')
            version = str(tls_value.get('tls_version') or '')
            version = {'TLSv1': 'TLSv1.0'}.get(version, version)
            if version in tls_cfg['flag_protocols']:
                add('high', 'tls', 'Legacy TLS version negotiated', str(tls_value['tls_version']), 'get_tls_info')

        redirect = value_of('get_http_redirect_check')
        if redirect:
            if redirect.get('served_over_plain_http'):
                add('medium', 'tls', 'Site is served over plain HTTP', 'HTTP requests are not redirected to HTTPS.', 'get_http_redirect_check')
            elif redirect.get('chain') and not redirect.get('upgrades_to_https') and redirect.get('final_url') is None:
                add('info', 'tls', 'HTTP to HTTPS behaviour unclear', 'Could not trace a final URL from port 80.', 'get_http_redirect_check')

        session_like = re.compile('|'.join(re.escape(h) for h in http_cfg.cookie_flags['session_cookie_name_hints']), re.I)
        cookies_out = (results.get('get_cookies') or {}).get('value') or {}
        for ep, cookies in cookies_out.items():
            if not isinstance(cookies, list):
                continue
            for c in cookies:
                name = c.get('name')
                if not name:
                    continue
                sensitive = bool(session_like.search(name))
                if not c.get('secure'):
                    add('medium' if sensitive else 'low', 'cookies', f'Cookie {name} lacks Secure flag', ep, 'get_cookies')
                if sensitive and not c.get('httponly'):
                    add('medium', 'cookies', f'Session-like cookie {name} lacks HttpOnly', ep, 'get_cookies')
                if sensitive and not c.get('samesite'):
                    add('low', 'cookies', f'Session-like cookie {name} lacks SameSite', ep, 'get_cookies')

        for ep, entry in entries('get_cors'):
            if not entry.get('CORS'):
                continue
            origin = entry.get('allow_origin')
            if entry.get('reflects_origin') and entry.get('allow_credentials'):
                add('high', 'cors', f'Arbitrary origin reflected with credentials ({ep})', origin, 'get_cors')
            elif entry.get('reflects_origin'):
                add('medium', 'cors', f'Arbitrary origin reflected ({ep})', origin, 'get_cors')
            elif origin == 'null':
                add('medium', 'cors', f'CORS allows the null origin ({ep})', '', 'get_cors')
            elif origin == '*':
                add('low', 'cors', f'CORS allows any origin ({ep})', 'Wildcard origin without credentials.', 'get_cors')

        critical_files = re.compile(
            r'^/(?:\.git/|\.env|\.htpasswd|\.ssh/|id_rsa|backup|site-backup|wp-config|config\.php\.bak|\.svn/|\.npmrc)', re.I)
        high_files = re.compile(r'^/(?:phpinfo|info\.php|test\.php|server-status|server-info|debug\.log|error_log|error\.log)', re.I)
        exposed = (results.get('get_exposed_files') or {}).get('value') or {}
        for path, info in exposed.items():
            if not isinstance(info, dict):
                continue
            sev = 'critical' if critical_files.match(path) else 'high' if high_files.match(path) else 'medium'
            add(sev, 'exposure', f'Sensitive file reachable: {path}',
                f"HTTP {info.get('status_code')}, validated={info.get('content_validated')}", 'get_exposed_files')

        for ep, entry in entries('get_server_info'):
            server = entry.get('server') or ''
            if re.search(r'\d+\.\d+', server):
                add('low', 'disclosure', f'Server version disclosed ({ep})', server, 'get_server_info')
            if entry.get('x_powered_by'):
                add('low', 'disclosure', f'X-Powered-By disclosed ({ep})', entry['x_powered_by'], 'get_server_info')
            if entry.get('x_aspnet_version'):
                add('low', 'disclosure', f'ASP.NET version disclosed ({ep})', entry['x_aspnet_version'], 'get_server_info')

        email = value_of('get_email_security')
        if email:
            spf, dmarc = email.get('spf', {}), email.get('dmarc', {})
            has_mail = bool(email['mx']['hosts']) and not email['mx']['null_mx']
            if has_mail and not spf.get('present'):
                add('medium', 'email', 'No SPF record', 'Domain receives mail but publishes no SPF policy.', 'get_email_security')
            if spf.get('policy') == 'pass (open to everyone)':
                add('high', 'email', 'SPF allows any sender (+all)', spf.get('raw', ''), 'get_email_security')
            if spf.get('multiple_records'):
                add('medium', 'email', 'Multiple SPF records', 'Evaluators return permerror when several records exist.', 'get_email_security')
            if spf.get('exceeds_10_lookup_limit'):
                add('medium', 'email', 'SPF exceeds 10 DNS lookups', f"{spf.get('dns_lookup_count')} lookups; evaluators return permerror.", 'get_email_security')
            if has_mail and not dmarc.get('present'):
                add('medium', 'email', 'No DMARC record', 'Spoofed mail is neither rejected nor reported.', 'get_email_security')
            elif dmarc.get('present') and (dmarc.get('policy') or '').lower() == 'none':
                add('low', 'email', 'DMARC policy is p=none', 'Monitoring only; no enforcement.', 'get_email_security')
            for note in email.get('assessment', []):
                if 'does not receive mail' in note:
                    add('low', 'email', 'Non-mail domain can be spoofed', note, 'get_email_security')

        dns_h = value_of('get_dns_hardening')
        if dns_h:
            if not dns_h['caa']['present']:
                add('info', 'dns', 'No CAA records', 'Any CA may issue certificates for this domain.', 'get_dns_hardening')
            if not dns_h['dnssec']['enabled']:
                add('info', 'dns', 'DNSSEC not enabled', 'No DS record at the parent zone.', 'get_dns_hardening')
            if dns_h['nameservers']['count'] == 1:
                add('low', 'dns', 'Single nameserver', 'No DNS redundancy.', 'get_dns_hardening')
            if dns_h['wildcard_dns']['detected']:
                add('info', 'dns', 'Wildcard DNS enabled', 'Random subdomains resolve; enumeration results may be noisy.', 'get_dns_hardening')

        rdap = value_of('get_rdap')
        if rdap and rdap.get('available'):
            age, left = rdap.get('domain_age_days'), rdap.get('days_until_expiry')
            if age is not None and age < 30:
                add('medium', 'registration', 'Domain registered less than 30 days ago', f'{age} days old', 'get_rdap')
            if left is not None and 0 <= left < 30:
                add('medium', 'registration', 'Domain registration expires within 30 days', f'{left} days left', 'get_rdap')
            elif left is not None and left < 0:
                add('high', 'registration', 'Domain registration has expired', f'{abs(left)} days ago', 'get_rdap')

        takeover = (results.get('get_takeover_candidates') or {}).get('value') or {}
        for c in takeover.get('candidates', []):
            add(c['risk'], 'takeover', f"Possible subdomain takeover: {c['subdomain']}",
                f"{c['reason']} (-> {c['final_target']})", 'get_takeover_candidates')

        for ep, entry in entries('get_sri_usage'):
            missing = entry.get('summary', {}).get('missing_sri_count', 0)
            if missing:
                add('low', 'supply_chain', f'{missing} third-party resources without SRI ({ep})',
                    'Compromised CDNs could inject code.', 'get_sri_usage')

        secret_severity = {
            'Stripe Live Secret Key': 'critical', 'Private key block': 'critical',
            'MongoDB connection string': 'critical', 'Postgres connection string with credentials': 'critical',
            'AWS Access Key ID': 'high', 'GitHub Personal Access Token': 'high', 'Slack Token': 'high',
            'SendGrid API Key': 'high', 'Anthropic API Key': 'high', 'OpenAI-style API Key': 'high',
            'Telegram Bot Token': 'high', 'Slack Webhook URL': 'high', 'Discord Webhook URL': 'high',
            'Generic key/token assignment': 'medium', 'Google API Key': 'medium',
            'Stripe Live Publishable Key': 'info',
        }
        js_out = (results.get('get_js_file_analysis') or {}).get('value') or {}
        for ep, files in js_out.items():
            if not isinstance(files, list):
                continue
            for f in files:
                for s in f.get('secrets_found', []):
                    sev = secret_severity.get(s['type'], 'low')
                    add(sev, 'secrets', f"{s['type']} in {f['file']}",
                        f"{s['match_count']} match(es), sample {s.get('sample_masked')}", 'get_js_file_analysis')
                if f.get('source_map_accessible'):
                    add('medium', 'disclosure', f"Source map publicly accessible: {f['source_map_url']}",
                        'Original source code can be reconstructed.', 'get_js_file_analysis')

        for ep, entry in (results.get('get_graphql_introspection') or {}).get('value', {}).items():
            if isinstance(entry, dict) and entry.get('introspection_enabled'):
                add('medium', 'api', f'GraphQL introspection enabled ({ep})', f"{entry.get('type_count')} types exposed", 'get_graphql_introspection')

        api = (results.get('get_api_discovery') or {}).get('value') or {}
        for path, info in api.items():
            if not isinstance(info, dict):
                continue
            if path.startswith('/actuator'):
                add('high', 'api', f'Spring actuator exposed: {path}', '', 'get_api_discovery')
            elif info.get('looks_like_api_spec'):
                add('medium', 'api', f'API specification exposed: {path}', '', 'get_api_discovery')
            elif path in ('/swagger-ui.html', '/swagger-ui/', '/redoc', '/api/redoc', '/graphiql'):
                add('low', 'api', f'API documentation UI reachable: {path}', '', 'get_api_discovery')

        for ep, entry in entries('get_allowed_methods'):
            for method, why in entry.get('risky_methods_present', {}).items():
                add('medium', 'methods', f'{method} method advertised ({ep})', why, 'get_allowed_methods')

        err_page = value_of('get_error_page_fingerprint')
        if err_page:
            if err_page.get('stack_trace_exposed'):
                add('high', 'disclosure', 'Stack trace or debug mode exposed on error page',
                    ', '.join(err_page['fingerprints_matched']), 'get_error_page_fingerprint')
            if err_page.get('takeover_risk'):
                add('high', 'takeover', 'Error page suggests a dangling hosting record',
                    ', '.join(err_page['fingerprints_matched']), 'get_error_page_fingerprint')

        for ep, entry in entries('get_mime_handling'):
            if entry.get('sniffing_risk'):
                add('low', 'headers', f'Content-type mismatch without nosniff ({ep})',
                    f"{entry.get('declared_content_type')} vs {entry.get('sniffed_content_type')}", 'get_mime_handling')

        for ep, entry in entries('get_cache_headers'):
            for flag in entry.get('risk_flags', []):
                sev = 'medium' if 'sensitive' in flag or 'cookie' in flag else 'info'
                add(sev, 'caching', f'{flag} ({ep})', '', 'get_cache_headers')

        for ep, entry in entries('get_forms'):
            for form in entry.get('forms', []):
                if form['has_password'] and (form['insecure_action']):
                    add('high', 'forms', 'Password form submits over plain HTTP', form['action'], 'get_forms')
                if form['has_password'] and form['external_action']:
                    add('medium', 'forms', 'Password form posts to another domain', form['action'], 'get_forms')
                if form['method'] == 'POST' and not form['csrf_token_field']:
                    add('low', 'forms', 'POST form without a visible CSRF token field',
                        f"{form['action']} (may rely on SameSite or header-based protection)", 'get_forms')

        for ep, entry in entries('get_external_resources'):
            for m in entry.get('mixed_content', []):
                add('medium' if m['active'] else 'low', 'tls',
                    f"{'Active' if m['active'] else 'Passive'} mixed content: {m['type']}", m['url'], 'get_external_resources')

        for source in ('get_trackers',):
            for ep, entry in entries(source):
                for v in entry.get('vendors', []):
                    if v['category'] == 'abuse':
                        add('high', 'abuse', f"Abuse-adjacent script: {v['name']} ({ep})",
                            f"confidence {v['confidence']}; {', '.join(v['samples'][:2])}", source)

        ads = value_of('get_ad_syndicates')
        if ads:
            aggressive = [v['name'] for v in ads.get('vendors', []) if v['category'] == 'ad_network_aggressive']
            if aggressive:
                add('low', 'reputation', 'Aggressive/pop-style ad networks present', ', '.join(aggressive), 'get_ad_syndicates')
            for v in ads.get('vendors', []):
                if v['category'] == 'abuse':
                    add('high', 'abuse', f"Abuse-adjacent script: {v['name']}", '', 'get_ad_syndicates')

        port_scan = value_of('get_port_scan')
        if port_scan:
            for ip, open_ports in port_scan.get('open_ports', {}).items():
                for p in open_ports:
                    svc = p['service']
                    if svc in RISKY_EXPOSED_SERVICES:
                        sev, reason = RISKY_EXPOSED_SERVICES[svc]
                        add(sev, 'exposure', f"{svc} exposed on {ip}:{p['port']}", reason, 'get_port_scan')

        dir_listing = value_of('get_open_directory_listing')
        if dir_listing:
            for path, info in dir_listing.items():
                add('medium', 'exposure', f'Directory listing enabled: {path}',
                    f"~{info.get('entry_count_guess')} entries visible", 'get_open_directory_listing')

        findings.sort(key=lambda f: (-self.severity_rank[f['severity']], f['category'], f['title']))
        return findings

    def run_audit(self, domain=None, profile='standard', probes=None, endpoints=None, workers=None, progress=None):
        """Run a profile or explicit probe list, then derive ranked findings and a summary."""
        domain = self._dom(domain)
        profiles = self.cfg.profiles.profiles
        if not probes and profile not in profiles:
            raise ValueError(f'unknown profile {profile!r} (available: {", ".join(profiles)})')
        names = list(probes) if probes else list(profiles[profile])
        workers = self._opt(workers, 'workers')
        started = time.time()
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futures = {n: pool.submit(self._run_probe, n, domain, endpoints) for n in names}
            for name, future in futures.items():
                results[name] = future.result()
                if progress:
                    progress(name)

        findings = self.derive_findings(results)
        counts = {sev: 0 for sev in self.severity_rank}
        for f in findings:
            counts[f['severity']] += 1
        failed = {n: r['error'] for n, r in results.items() if isinstance(r, dict) and r.get('error')}
        return {
            'domain': domain,
            'time': started,
            'elapsed_seconds': round(time.time() - started, 2),
            'profile': None if probes else profile,
            'probes_run': names,
            'results': results,
            'findings': findings,
            'summary': {'severity_counts': counts, 'finding_count': len(findings), 'probes_failed': failed},
        }

    def save_report(self, report, path):
        """Write a report (or any probe output) as JSON."""
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, default=lambda o: sorted(o) if isinstance(o, set) else str(o))
        return path

    def report_to_markdown(self, report):
        """Render an audit report as readable Markdown."""
        summary = report['summary']
        lines = [
            f"# webspy audit: {report['domain']}",
            '',
            f"- Profile: {report.get('profile') or 'custom'}",
            f"- Probes run: {len(report['probes_run'])}",
            f"- Elapsed: {report['elapsed_seconds']}s",
            '',
            '## Summary',
            '',
            '| Severity | Count |',
            '|---|---|',
        ]
        for sev in sorted(self.severity_rank, key=lambda s: -self.severity_rank[s]):
            lines.append(f"| {sev} | {summary['severity_counts'][sev]} |")
        lines += ['', '## Findings', '']
        if not report['findings']:
            lines.append('No findings.')
        current = None
        for f in report['findings']:
            if f['severity'] != current:
                current = f['severity']
                lines += ['', f'### {current.capitalize()}', '']
            detail = f" — {f['detail']}" if f['detail'] else ''
            lines.append(f"- **{f['title']}** [{f['category']}]{detail}")
        if summary['probes_failed']:
            lines += ['', '## Probe errors', '']
            for name, err in summary['probes_failed'].items():
                lines.append(f'- `{name}`: {err}')
        return '\n'.join(lines) + '\n'

    def report_to_csv(self, report):
        """Render findings as CSV text (severity, category, title, detail, source) — handy for spreadsheets or ticket import."""
        import csv
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['severity', 'category', 'title', 'detail', 'source'])
        for f in report['findings']:
            writer.writerow([f['severity'], f['category'], f['title'], f['detail'], f['source']])
        return buf.getvalue()

    def report_to_html(self, report):
        """Render an audit report as a single self-contained, shareable HTML page."""
        summary = report['summary']
        sev_colors = {
            'critical': '#7f1d1d', 'high': '#b91c1c', 'medium': '#b45309',
            'low': '#1d4ed8', 'info': '#4b5563',
        }
        rows = []
        for f in report['findings']:
            color = sev_colors.get(f['severity'], '#374151')
            detail = html.escape(f['detail']) if f['detail'] else ''
            rows.append(
                '<tr>'
                f'<td><span style="background:{color};color:#fff;padding:2px 8px;'
                f'border-radius:4px;font-size:12px;text-transform:uppercase">{html.escape(f["severity"])}</span></td>'
                f'<td>{html.escape(f["category"])}</td>'
                f'<td>{html.escape(f["title"])}</td>'
                f'<td style="color:#555">{detail}</td>'
                '</tr>'
            )
        counts_row = ''.join(
            f'<div style="padding:8px 14px;border-radius:6px;background:{sev_colors.get(s, "#374151")};'
            f'color:#fff;font-size:13px">{s}: {summary["severity_counts"][s]}</div>'
            for s in sorted(self.severity_rank, key=lambda s: -self.severity_rank[s])
        )
        body_rows = ''.join(rows) if rows else '<tr><td colspan="4">No findings.</td></tr>'
        return (
            '<!DOCTYPE html><html><head><meta charset="utf-8">'
            f'<title>webspy audit: {html.escape(report["domain"])}</title>'
            '<style>'
            'body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#111;background:#fafafa}'
            'table{border-collapse:collapse;width:100%;background:#fff}'
            'td,th{padding:8px 10px;border-bottom:1px solid #eee;text-align:left;font-size:14px;vertical-align:top}'
            'h1{font-size:20px}.meta{color:#666;font-size:13px;margin-bottom:1rem}'
            '.counts{display:flex;gap:8px;margin-bottom:1.5rem;flex-wrap:wrap}'
            '</style></head><body>'
            f'<h1>webspy audit: {html.escape(report["domain"])}</h1>'
            f'<div class="meta">Profile: {html.escape(str(report.get("profile") or "custom"))} &middot; '
            f'Probes run: {len(report["probes_run"])} &middot; Elapsed: {report["elapsed_seconds"]}s</div>'
            f'<div class="counts">{counts_row}</div>'
            '<table><thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Detail</th></tr></thead>'
            f'<tbody>{body_rows}</tbody></table>'
            '</body></html>'
        )


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(prog='webspy', description='Passive web reconnaissance and audit toolkit.')
    parser.add_argument('domain', nargs='?', help='domain or URL to inspect')
    parser.add_argument('--profile', default='standard', help='audit profile name (' + ', '.join(AUDIT_PROFILES) + ' by default)')
    parser.add_argument('--probe', action='append', help='run only this probe (repeatable)')
    parser.add_argument('--endpoints', default='/', help='comma-separated paths for endpoint-based probes')
    parser.add_argument('--workers', type=int, default=None)
    parser.add_argument('--config', action='append', default=[], help='config directory or <section>.json file layered over the defaults (repeatable)')
    parser.add_argument('--json', dest='json_path', help='write the full report as JSON')
    parser.add_argument('--markdown', dest='md_path', help='write the findings as Markdown')
    parser.add_argument('--csv', dest='csv_path', help='write the findings as CSV')
    parser.add_argument('--html', dest='html_path', help='write the findings as a self-contained HTML page')
    parser.add_argument('--list-probes', action='store_true')
    parser.add_argument('--i-am-authorized', action='store_true',
                        help='required to run active probes (get_port_scan, get_subdomain_bruteforce, '
                             'get_open_directory_listing) by name via --probe; confirms you are authorized '
                             'to test the target host(s)')
    args = parser.parse_args(argv)
    spy = Passive(*args.config)

    if args.list_probes:
        for name, doc in spy.list_probes():
            print(f'{name:32s} {doc}')
        return 0
    if not args.domain:
        parser.error('a domain is required')

    active_probes = {'get_port_scan', 'get_subdomain_bruteforce', 'get_open_directory_listing'}
    if args.probe and (set(args.probe) & active_probes) and not args.i_am_authorized:
        parser.error(
            'the requested probe(s) actively connect to every port/path they check '
            f'({", ".join(sorted(set(args.probe) & active_probes))}); re-run with --i-am-authorized '
            'to confirm you are authorized to test this host'
        )

    endpoints = [e.strip() for e in args.endpoints.split(',') if e.strip()]
    report = spy.run_audit(
        args.domain, profile=args.profile, probes=args.probe, endpoints=endpoints,
        workers=args.workers, progress=lambda n: print(f'  done: {n}', file=sys.stderr),
    )
    if args.json_path:
        spy.save_report(report, args.json_path)
    if args.md_path:
        with open(args.md_path, 'w', encoding='utf-8') as fh:
            fh.write(spy.report_to_markdown(report))
    if args.csv_path:
        with open(args.csv_path, 'w', encoding='utf-8', newline='') as fh:
            fh.write(spy.report_to_csv(report))
    if args.html_path:
        with open(args.html_path, 'w', encoding='utf-8') as fh:
            fh.write(spy.report_to_html(report))

    counts = report['summary']['severity_counts']
    print(f"\n{report['domain']}: " + ', '.join(f'{counts[s]} {s}' for s in sorted(spy.severity_rank, key=lambda x: -spy.severity_rank[x])))
    for f in report['findings'][:40]:
        print(f"  [{f['severity']:8s}] {f['title']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())