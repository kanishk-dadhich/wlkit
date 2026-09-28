#!/usr/bin/env python3
"""
wlkit - Wordlist Kit
====================
An educational, all-in-one wordlist toolkit built around the techniques taught in
the TryHackMe "Introduction to Wordlists" room. It consolidates the jobs normally
split across crunch, CeWL, CUPP, username-anarchy and hashcat/john rules into one
CLI so you can see how each piece works.

Subcommands
-----------
  gen       crunch-style pattern/charset generation
  extract   CeWL-style unique word extraction from text or HTML
  profile   CUPP-style personalised wordlist from someone's public info
  users     username-format generation from a list of full names
  mutate    rule-based mutation (case, leet, append years/numbers/symbols)
  combine   merge / dedupe / sort multiple wordlists
  use       build a gobuster/hydra/ffuf command line from a wordlist
  wizard    interactive menu: asks what you need, builds the list + command
  auto      "thinking" mode: give a URL, it reasons + builds the whole attack
  harvest   scrape a URL (+cookie) into a users file AND a passwords file
  cupp      faithful Mebus/cupp mechanism: profile -> wordlist (interactive/flags/URL)
  osint     people/keywords (file, names, or a PUBLIC page) -> target wordlist

For authorised security testing and learning only. Only run generated lists
against systems you are explicitly permitted to test.

Author : Kanishk Dadhich
Tips   : https://razorpay.me/@kanishkdadhich
GitHub : https://github.com/kanishk-dadhich
X      : https://x.com/whotfbunny
LinkedIn: https://www.linkedin.com/in/kanishk-dadhich
Email  : kanishkdadhich123@gmail.com
"""

from __future__ import annotations

__author__ = "Kanishk Dadhich"
__version__ = "1.0"
TIPS_URL = "https://razorpay.me/@kanishkdadhich"
SOCIALS = {
    "GitHub": "https://github.com/kanishk-dadhich",
    "X": "https://x.com/whotfbunny",
    "LinkedIn": "https://www.linkedin.com/in/kanishk-dadhich",
    "Email": "kanishkdadhich123@gmail.com",
}

import argparse
import html
import itertools
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------- #
# Appearance (ANSI colours + banner). Auto-disables when not a TTY / NO_COLOR.
# --------------------------------------------------------------------------- #

_USE_COLOR = sys.stdout.isatty() and sys.stderr.isatty() and "NO_COLOR" not in os.environ

_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "ital": "\033[3m",
    "red": "\033[38;5;203m", "green": "\033[38;5;42m", "yellow": "\033[38;5;221m",
    "blue": "\033[38;5;39m", "cyan": "\033[38;5;51m", "magenta": "\033[38;5;207m",
    "orange": "\033[38;5;215m", "gray": "\033[38;5;245m", "purple": "\033[38;5;141m",
    "lime": "\033[38;5;190m", "pink": "\033[38;5;211m",
}


def c(text, *styles):
    """Wrap text in ANSI styles (no-op when colour is disabled)."""
    if not _USE_COLOR or not styles:
        return str(text)
    return "".join(_ANSI.get(s, "") for s in styles) + str(text) + _ANSI["reset"]


# colour per reasoning-trace tag
_TAG_STYLE = {
    "PHASE": ("purple", "bold"), "RECON": ("cyan",), "OBSERVATION": ("green",),
    "HYPOTHESIS": ("yellow",), "PLAN": ("blue",), "DECISION": ("lime", "bold"),
    "RESULT": ("red", "bold"), "NOTE": ("gray",), "VALIDATE": ("orange", "bold"),
}

WLKIT_BANNER = r"""
                _  _    _  _
 __      __ | |__ (_)| |_
 \ \ /\ / / | | / /| || __|    Wordlist Kit
  \ V  V /  | |/ / | || |_     recon - profile - rules - attack
   \_/\_/   |_|\_\ |_| \__|
"""


def _banner(subtitle: str = ""):
    art = c(WLKIT_BANNER, "cyan", "bold") if _USE_COLOR else WLKIT_BANNER
    line = c(f"  by {__author__}", "gray") + c("   •   ", "dim") + \
        c(f"tip: {TIPS_URL}", "pink")
    out = art + "\n" + line
    if subtitle:
        out += "\n  " + c(subtitle, "dim", "ital")
    return out


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

# crunch-style placeholder charsets
CHARSETS = {
    "@": "abcdefghijklmnopqrstuvwxyz",       # lowercase
    ",": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",       # uppercase
    "%": "0123456789",                       # digits
    "^": "!@#$%^&*()-_+=",                    # symbols
}

LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "g": "9", "b": "8"}


def write_lines(lines, out_path: str | None) -> int:
    """Write an iterable of strings to a file or stdout. Returns count written."""
    n = 0
    if out_path:
        with open(out_path, "w", encoding="utf-8", errors="replace") as fh:
            for line in lines:
                fh.write(line + "\n")
                n += 1
    else:
        for line in lines:
            sys.stdout.write(line + "\n")
            n += 1
    return n


def read_words(path: str) -> list[str]:
    return [w.rstrip("\n") for w in Path(path).read_text(encoding="utf-8", errors="replace").splitlines()]


# --------------------------------------------------------------------------- #
# gen  (crunch-style)
# --------------------------------------------------------------------------- #

def cmd_gen(args):
    """
    Two modes:
      --pattern "pass@%"   -> expand crunch placeholders (@ , % ^) + literals
      (min max charset)    -> every combination of `charset` of length min..max
    """
    if args.pattern:
        # Build a list of possible characters for each position.
        slots = []
        i = 0
        pat = args.pattern
        while i < len(pat):
            c = pat[i]
            if c == "\\" and i + 1 < len(pat):          # escaped literal
                slots.append([pat[i + 1]])
                i += 2
                continue
            slots.append(list(CHARSETS.get(c, c)))       # placeholder or literal
            i += 1
        combos = itertools.product(*slots)
        lines = ("".join(t) for t in combos)
        n = write_lines(lines, args.output)
    else:
        if args.min is None or args.max is None:
            sys.exit("gen: provide --pattern, or both min and max lengths")
        charset = args.charset or (CHARSETS["@"] + CHARSETS["%"])
        def brute():
            for length in range(args.min, args.max + 1):
                for combo in itertools.product(charset, repeat=length):
                    yield "".join(combo)
        n = write_lines(brute(), args.output)
    _report(n, args.output)


# --------------------------------------------------------------------------- #
# extract  (CeWL-style)
# --------------------------------------------------------------------------- #

def _load_source(src: str, strip_html_default: bool, cookie: str | None = None) -> tuple[str, bool]:
    """Return (text, is_html). Accepts a URL (fetched, optionally authenticated) or a file."""
    if re.match(r"^https?://", src, re.I):
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"}
        if cookie:
            headers["Cookie"] = cookie
        req = urllib.request.Request(src, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001 - surface any fetch problem cleanly
            sys.exit(f"[wlkit] could not fetch {src}: {exc}")
        return data, True  # a fetched page is HTML -> strip by default
    p = Path(src)
    if not p.exists():
        sys.exit(f"[wlkit] no such file: {src}\n"
                 f"        (give a local file path, or an http(s):// URL to fetch)")
    return p.read_text(encoding="utf-8", errors="replace"), strip_html_default


def cmd_extract(args):
    raw, force_strip = _load_source(args.input, args.strip_html, getattr(args, "cookie", None))
    if force_strip:
        args.strip_html = True
    if args.strip_html:
        raw = re.sub(r"<script.*?</script>", " ", raw, flags=re.S | re.I)
        raw = re.sub(r"<style.*?</style>", " ", raw, flags=re.S | re.I)
        raw = re.sub(r"<[^>]+>", " ", raw)
        raw = html.unescape(raw)
    words = re.findall(r"[A-Za-z][A-Za-z0-9'\-]*", raw)

    seen, ordered = set(), []
    for w in words:
        if len(w) < args.min_length or len(w) > args.max_length:
            continue
        if args.lowercase:
            w = w.lower()
        if w not in seen:
            seen.add(w)
            ordered.append(w)
    if args.sort:
        ordered.sort(key=str.lower)
    n = write_lines(ordered, args.output)
    _report(n, args.output)


# --------------------------------------------------------------------------- #
# profile  (CUPP-style)
# --------------------------------------------------------------------------- #

def _leet_variants(word: str) -> set[str]:
    """Return the word plus a full-leet variant."""
    out = {word}
    leet = "".join(LEET_MAP.get(c.lower(), c) for c in word)
    out.add(leet)
    return out


def _case_variants(word: str) -> set[str]:
    return {word, word.lower(), word.upper(), word.capitalize()}


def cmd_profile(args):
    """CUPP-style: seed from personal terms, combine, then decorate with years/suffixes."""
    seeds: list[str] = []
    for src in (args.words or []):
        seeds.extend(t for t in re.split(r"[\s,]+", src) if t)
    if args.pet:
        seeds.extend(args.pet)

    seeds = [s for s in dict.fromkeys(seeds) if s]  # dedupe, keep order
    if not seeds:
        sys.exit("profile: give at least --words (names/dates/pets/keywords)")

    # base = seeds + case variants (+leet if asked)
    base: set[str] = set()
    for s in seeds:
        base |= _case_variants(s)
        if args.leet:
            for cv in list(base):
                base |= _leet_variants(cv)

    # pairwise concatenation of seeds (John + Smith -> JohnSmith, johnsmith ...)
    if args.combine:
        for a, b in itertools.permutations(seeds, 2):
            base.add(a + b)
            base.add((a + b).lower())
            base.add(a.capitalize() + b.capitalize())

    # suffixes: years + a small number/symbol set
    this_year = datetime.now().year
    years = [str(y) for y in range(this_year - args.years_back, this_year + 1)]
    suffixes = [""] + years + ["1", "12", "123", "1234", "007", "00"]
    symbols = ["", "!", "@", "#", "$", "!!", "123!"]

    results: set[str] = set()
    for w in base:
        if len(w) < args.min_length:
            continue
        for suf in suffixes:
            for sym in symbols:
                cand = f"{w}{suf}{sym}"
                if args.min_length <= len(cand) <= args.max_length:
                    results.add(cand)

    ordered = sorted(results)
    n = write_lines(ordered, args.output)
    _report(n, args.output)


# --------------------------------------------------------------------------- #
# users  (username-format generation)
# --------------------------------------------------------------------------- #

def cmd_users(args):
    names = read_words(args.input)
    out: list[str] = []
    seen = set()

    def add(u: str):
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)

    for line in names:
        parts = [p for p in re.split(r"[\s]+", line.strip()) if p]
        if not parts:
            continue
        first = parts[0].lower()
        last = parts[-1].lower()
        fi, li = first[0], last[0]
        # common corporate username schemes
        add(f"{first}.{last}")     # john.smith
        add(f"{first}{last}")      # johnsmith
        add(f"{fi}{last}")         # jsmith
        add(f"{fi}.{last}")        # j.smith
        add(f"{first}{li}")        # johns
        add(f"{last}{fi}")         # smithj
        add(f"{first}_{last}")     # john_smith
        add(f"{first}-{last}")     # john-smith
        add(first)                 # john
        add(last)                  # smith
        if args.domain:
            for base in list(out):
                if "@" not in base:
                    add(f"{base}@{args.domain}")

    n = write_lines(out, args.output)
    _report(n, args.output)


# --------------------------------------------------------------------------- #
# mutate  (rule-based, hashcat/john-lite)
# --------------------------------------------------------------------------- #

def _apply_template(word: str, template: str, years: list, syms: list, nums: list):
    """Expand a rule template for one word. Placeholders:
      {word}/{w}=as-is  {cap}/{W}=Capitalized  {upper}/{U}  {lower}/{l}
      {leet}  {year}  {sym}  {num}   (literals like '!' stay as-is)
    {year}/{sym}/{num} expand over their sets (cartesian product)."""
    base = {
        "{word}": word, "{w}": word,
        "{cap}": word.capitalize(), "{W}": word.capitalize(),
        "{upper}": word.upper(), "{U}": word.upper(),
        "{lower}": word.lower(), "{l}": word.lower(),
        "{leet}": "".join(LEET_MAP.get(c, c) for c in word.lower()),
    }
    t = template
    for k, v in base.items():
        t = t.replace(k, v)
    # expand the multi-valued tokens as a cartesian product
    variants = [t]
    for token, values in (("{year}", years), ("{sym}", syms), ("{num}", nums)):
        if any(token in v for v in variants):
            variants = [v.replace(token, val) for v in variants for val in values]
    return variants


def cmd_mutate(args):
    words = read_words(args.input)
    this_year = datetime.now().year
    years = [str(y) for y in range(this_year - args.years_back, this_year + 1)]
    num_suffix = ["1", "12", "123", "1234", "01", "007", "!", "@", "#", "$", "123!"]

    seen: set[str] = set()
    out: list[str] = []

    def add(w: str):
        if args.min_length <= len(w) <= args.max_length and w not in seen:
            seen.add(w)
            out.append(w)

    # ---- template mode: express an exact described rule ----------------- #
    if getattr(args, "template", None):
        syms = (args.symbols.split(",") if args.symbols else ["!", "@", "#", "$"])
        if getattr(args, "nums", None):
            m = re.fullmatch(r"(\d+)-(\d+)", args.nums.strip())
            if m:                                   # range form: 0-100
                nums = [str(i) for i in range(int(m.group(1)), int(m.group(2)) + 1)]
            else:                                   # comma list
                nums = [n.strip() for n in args.nums.split(",") if n.strip()]
        else:
            nums = ["1", "12", "123", "1234", "01", "007", "69", "00"]
        for w in words:
            for cand in _apply_template(w, args.template, years, syms, nums):
                add(cand)
        n = write_lines(out, args.output)
        _report(n, args.output)
        return

    for w in words:
        variants = {w}
        if args.case:
            variants |= _case_variants(w)
        if args.leet:
            for v in list(variants):
                variants |= _leet_variants(v)
        for v in variants:
            add(v)
            if args.append:
                for s in years + num_suffix:
                    add(v + s)
            if args.prepend:
                for s in num_suffix:
                    add(s + v)

    n = write_lines(out, args.output)
    _report(n, args.output)


# --------------------------------------------------------------------------- #
# combine  (merge / dedupe / sort)
# --------------------------------------------------------------------------- #

def cmd_combine(args):
    from collections import Counter
    counter: Counter[str] = Counter()
    order: list[str] = []
    for path in args.inputs:
        for w in read_words(path):
            w = w.rstrip()
            if not w:
                continue
            if w not in counter:
                order.append(w)
            counter[w] += 1

    if args.by_frequency:
        items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
        lines = [w for w, _ in items]
    elif args.sort:
        lines = sorted(counter.keys(), key=str.lower)
    else:
        lines = order  # first-seen order, deduped

    n = write_lines(lines, args.output)
    _report(n, args.output)


# --------------------------------------------------------------------------- #
# use  (gobuster / hydra / ffuf command builder)
# --------------------------------------------------------------------------- #

def _build_command(args) -> list[str]:
    """Return an argv list for the chosen tool/mode. Raises SystemExit on misuse."""
    wl = args.wordlist
    threads = str(args.threads)

    def need(*fields):
        missing = [f for f in fields if getattr(args, f, None) in (None, "")]
        if missing:
            sys.exit(f"use {args.tool}/{args.mode}: missing --{', --'.join(missing)}")

    if args.tool == "gobuster":
        if args.mode == "dir":
            need("url")
            cmd = ["gobuster", "dir", "-u", args.url, "-w", wl, "-t", threads]
            if args.extensions:
                cmd += ["-x", args.extensions]
            if args.status:
                cmd += ["-s", args.status, "-b", ""]
        elif args.mode == "dns":
            need("domain")
            cmd = ["gobuster", "dns", "-d", args.domain, "-w", wl, "-t", threads]
        elif args.mode == "vhost":
            need("url")
            cmd = ["gobuster", "vhost", "-u", args.url, "-w", wl, "-t", threads, "--append-domain"]
        else:
            sys.exit("gobuster modes: dir | dns | vhost")

    elif args.tool == "ffuf":
        need("url")
        # user puts FUZZ in the URL, e.g. http://site/FUZZ  or  ...?id=FUZZ
        cmd = ["ffuf", "-w", wl, "-u", args.url, "-t", threads]
        if args.extensions:
            cmd += ["-e", args.extensions]
        if args.match_codes:
            cmd += ["-mc", args.match_codes]
        if args.filter_size:
            cmd += ["-fs", args.filter_size]

    elif args.tool == "hydra":
        need("target")
        # login source: single user, or a users file
        if args.userlist:
            login = ["-L", args.userlist]
        elif args.user:
            login = ["-l", args.user]
        else:
            sys.exit("use hydra: give --user or --userlist")
        pw = ["-P", wl]  # the wordlist is the password list here

        if args.mode == "http-post-form":
            need("path", "fail")
            # path like: /login:username=^USER^&password=^PASS^:F=incorrect
            form = f"{args.path}:{args.body}:{args.fail}" if args.body else f"{args.path}:{args.fail}"
            cmd = ["hydra", *login, *pw, "-s", str(args.port or 80),
                   args.target, "http-post-form", form, "-t", threads]
        elif args.mode == "http-get-form":
            need("path", "fail")
            form = f"{args.path}:{args.body}:{args.fail}" if args.body else f"{args.path}:{args.fail}"
            cmd = ["hydra", *login, *pw, args.target, "http-get-form", form, "-t", threads]
        elif args.mode in ("ssh", "ftp", "smb", "rdp", "mysql", "postgres"):
            cmd = ["hydra", *login, *pw, args.target, args.mode, "-t", threads]
            if args.port:
                cmd += ["-s", str(args.port)]
        else:
            sys.exit("hydra modes: ssh | ftp | smb | rdp | mysql | postgres | "
                     "http-post-form | http-get-form")
    else:
        sys.exit("tool must be gobuster | ffuf | hydra")

    return cmd


def cmd_use(args):
    if not Path(args.wordlist).exists():
        sys.stderr.write(f"[wlkit] warning: wordlist '{args.wordlist}' not found on disk\n")
    cmd = _build_command(args)
    printable = " ".join(shlex.quote(c) for c in cmd)
    print(printable)

    if args.run:
        sys.stderr.write(
            "\n[wlkit] --run given. Only launch this against systems you are "
            "explicitly authorised to test.\n"
        )
        try:
            confirm = input("[wlkit] Type 'yes' to execute now: ").strip().lower()
        except EOFError:
            confirm = ""
        if confirm != "yes":
            sys.stderr.write("[wlkit] aborted; command not executed.\n")
            return
        try:
            subprocess.run(cmd)
        except FileNotFoundError:
            sys.exit(f"[wlkit] '{cmd[0]}' not installed or not in PATH.")


# --------------------------------------------------------------------------- #
# wizard  (interactive menu-driven builder)
# --------------------------------------------------------------------------- #

def _ns(**kw):
    """Build an argparse.Namespace pre-filled with sensible defaults for reuse."""
    return argparse.Namespace(**kw)


def _ask(prompt: str, default: str | None = None) -> str:
    tail = c(f" [{default}]", "dim") if default else ""
    try:
        val = input(f"  {c('?', 'yellow', 'bold')} {prompt}{tail}{c(':', 'dim')} ").strip()
    except EOFError:
        # No more input on the stream: don't spin, exit cleanly.
        print("\n[wlkit] input closed - aborting wizard.")
        sys.exit(1)
    return val or (default or "")


def _menu(title: str, options: list[tuple[str, str]]) -> str:
    """options = [(key, description)]. Returns the chosen key."""
    print(f"\n{c('?', 'yellow', 'bold')} {c(title, 'bold')}")
    for i, opt in enumerate(options, 1):
        key, desc = opt[0], opt[1]
        badge = opt[2] if len(opt) > 2 else ""
        badge_txt = (" " + c(f" {badge} ", "green", "bold")) if badge else ""
        print(f"    {c(str(i) + ')', 'cyan', 'bold')} "
              f"{c(f'{key:<22}', 'lime')} {c(desc, 'gray')}{badge_txt}")
    for _ in range(10):  # bounded retries; _ask exits on EOF
        raw = _ask("choose number")
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        print(c("    -- enter a number from the list --", "red"))
    sys.exit("[wlkit] too many invalid choices - aborting.")


def _yesno(prompt: str, default=False) -> bool:
    d = "Y/n" if default else "y/N"
    val = _ask(f"{prompt} ({d})").lower()
    if not val:
        return default
    return val.startswith("y")


def _wl_dir() -> Path:
    return Path(__file__).resolve().parent


def cmd_wizard(args):
    print(_banner("I'll ask what you need, then build it  ·  authorised / lab targets only"))

    goal = _menu(
        "What do you want to do?",
        [
            ("auto-attack",       "intel-driven: scrape a page, learn the rule, brute-force",
                                  "★ RECOMMENDED"),
            ("content-discovery", "find hidden dirs/files/endpoints (gobuster/ffuf)"),
            ("break-login",       "brute-force a login form or service (hydra)"),
            ("subdomain",         "enumerate subdomains / vhosts (gobuster)"),
            ("cupp",              "CUPP profiler (name/birthdate -> wordlist)"),
            ("osint",             "OSINT wordlist from people/keywords (file/names/public page)"),
            ("build-only",        "just build a wordlist, no command"),
        ],
    )

    if goal == "auto-attack":
        _wizard_auto()
    elif goal == "content-discovery":
        _wizard_content()
    elif goal == "subdomain":
        _wizard_subdomain()
    elif goal == "break-login":
        _wizard_login()
    elif goal == "cupp":
        _wizard_cupp()
    elif goal == "osint":
        _wizard_osint()
    else:
        wl = _wizard_build_list("wordlist.txt")
        print(f"\n[+] Wordlist ready: {wl}")


# ---- auto-attack (interactive front-end for cmd_auto) ------------------- #

def _wizard_auto():
    print("\n-- Auto attack: I'll ask, then scrape + build + run --")
    service = _menu("What service are we attacking?",
                    [("web", "a web login form"), ("ssh", "SSH"), ("ftp", "FTP"),
                     ("smb", "SMB"), ("mysql", "MySQL"), ("postgres", "PostgreSQL")])
    if service == "web":
        target = _ask("web login URL (e.g. http://10.49.152.19:5002)")
    else:
        target = _ask(f"{service} host (e.g. 10.49.152.19)")

    # intel source
    intel_url = intel_host = None
    if _yesno("is there a page with keywords / a password-habit tip to mine?",
              service != "web"):
        intel_url = _ask("intel URL (e.g. http://10.49.152.19:5003/)",
                         target if service == "web" else None)
        if _yesno("is that a vhost served by IP (need a Host header)?", False):
            intel_host = _ask("Host header (e.g. social.thm)")

    # cookie
    cookie = None
    if _yesno("does any page need login (send a session cookie)?", False):
        cookie = _ask("paste Cookie header") or None

    # username
    user = userlist = None
    if service == "web" and _yesno("let me auto-figure the username?", False):
        pass  # cmd_auto will handle it
    else:
        if _yesno("do you have ONE username?", True):
            user = _ask("username")
        else:
            userlist = _ask("path to username list")

    # wordlist choice: rockyou by default, custom only if asked
    wl_choice = _menu("Which password wordlist?",
                      [("rockyou", "use rockyou.txt (default)"),
                       ("make", "build a targeted list from intel/rule/personal data"),
                       ("file", "use a wordlist file I already have")])
    make_wordlist = wl_choice == "make"
    wordlist = _ask("path to wordlist") if wl_choice == "file" else None

    no_site = False
    if make_wordlist:
        no_site = not _yesno("also use broad site keywords as a fallback?", True)
    run = _yesno("run the attack now (else just build + print command)?", False)

    ns = _ns(target=target, service=service, cookie=cookie, intel_url=intel_url,
             intel_host=intel_host, user=user, userlist=userlist,
             no_site_words=no_site, make_wordlist=make_wordlist, wordlist=wordlist,
             run=run)
    cmd_auto(ns)


# ---- cupp (interactive front-end for cmd_cupp) -------------------------- #

def _wizard_cupp():
    print("\n-- CUPP profiler --")
    src = _menu("Where does the profile come from?",
                [("ask", "ask me the details (name, birthdate, ...)"),
                 ("url", "auto-fill from a profile page URL")])
    if src == "url":
        from_url = _ask("profile page URL")
        cookie = None
        if _yesno("does it need login (cookie)?", False):
            cookie = _ask("paste Cookie header") or None
        ns = _ns(interactive=False, from_url=from_url, cookie=cookie,
                 name=None, surname=None, nick=None, birthdate=None,
                 wife=None, wifen=None, wifeb=None, kid=None, kidn=None, kidb=None,
                 pet=None, company=None, words=None,
                 special=_yesno("append special chars?", True),
                 randnum=_yesno("append random numbers?", True),
                 leet=_yesno("leet mode?", True),
                 years=None, numfrom=0, numto=100, wcfrom=5, wcto=12,
                 output=_ask("output file", "cupp.txt"))
    else:
        ns = _ns(interactive=True, from_url=None, cookie=None,
                 name=None, surname=None, nick=None, birthdate=None,
                 wife=None, wifen=None, wifeb=None, kid=None, kidn=None, kidb=None,
                 pet=None, company=None, words=None,
                 special=False, randnum=False, leet=False,
                 years=None, numfrom=0, numto=100, wcfrom=5, wcto=12,
                 output=_ask("output file", "cupp.txt"))
    cmd_cupp(ns)


# ---- osint (interactive front-end for cmd_osint) ----------------------- #

def _wizard_osint():
    print("\n-- OSINT wordlist (public / imported data only) --")
    src = _menu("Where does the people/keyword data come from?",
                [("names", "I'll type names inline"),
                 ("import", "a file I already have (txt/csv)"),
                 ("url", "a PUBLIC page (team/about) to mine")])
    names = import_file = from_url = cookie = host = None
    if src == "names":
        names = [_ask("names (comma separated, e.g. 'John Smith, Jane Doe')")]
    elif src == "import":
        import_file = _ask("path to the OSINT file")
    else:
        from_url = _ask("public page URL")
        if _yesno("does it need a cookie?", False):
            cookie = _ask("paste Cookie header") or None
        if _yesno("is it a vhost served by IP (Host header)?", False):
            host = _ask("Host header")
    company = _ask("company / employer keyword (blank to skip)", "") or None
    kw = _ask("extra keywords (comma, blank to skip)", "")
    keywords = [w.strip() for w in kw.split(",") if w.strip()] or None
    ns = _ns(names=names, import_file=import_file, from_url=from_url, cookie=cookie,
             host=host, company=company, keywords=keywords,
             leet=_yesno("add leetspeak?", True),
             deep=_yesno("deep mode (special chars + random numbers, bigger)?", False),
             big=_yesno("expand numbers 0-100 (bigger)?", False),
             output=_ask("output file", "osint_wordlist.txt"))
    cmd_osint(ns)


# ---- content discovery -------------------------------------------------- #

def _pick_content_list() -> str:
    common = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ]
    opts = [(p, "exists" if Path(p).exists() else "not found") for p in common]
    opts.append(("custom", "type my own path"))
    choice = _menu("Which content wordlist?", opts)
    if choice == "custom":
        return _ask("path to wordlist")
    return choice


def _wizard_content():
    tool = _menu("Which tool?", [("gobuster", "classic dir brute"),
                                 ("ffuf", "fast fuzzer, FUZZ in URL")])
    url = _ask("target URL (e.g. http://10.49.152.19:5002)")
    wl = _pick_content_list()
    exts = _ask("file extensions to try (comma, blank for none)", "")
    if tool == "gobuster":
        ns = _ns(tool="gobuster", mode="dir", wordlist=wl, url=url, domain=None,
                 target=None, port=None, threads=40, extensions=exts or None,
                 status=None, match_codes=None, filter_size=None, user=None,
                 userlist=None, path=None, body=None, fail=None, run=False)
    else:
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        mc = _ask("match status codes", "200,301,302,401,403")
        ns = _ns(tool="ffuf", mode="", wordlist=wl, url=url, domain=None,
                 target=None, port=None, threads=40, extensions=exts or None,
                 status=None, match_codes=mc, filter_size=None, user=None,
                 userlist=None, path=None, body=None, fail=None, run=False)
    _emit_and_offer(ns)


# ---- subdomain / vhost -------------------------------------------------- #

def _wizard_subdomain():
    mode = _menu("DNS subdomains or HTTP vhosts?",
                 [("dns", "resolve subdomains"), ("vhost", "Host-header vhosts")])
    wl = _ask("subdomain wordlist path",
              "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    if mode == "dns":
        domain = _ask("domain (e.g. tryfinanceme.local)")
        ns = _ns(tool="gobuster", mode="dns", wordlist=wl, url=None, domain=domain,
                 target=None, port=None, threads=40, extensions=None, status=None,
                 match_codes=None, filter_size=None, user=None, userlist=None,
                 path=None, body=None, fail=None, run=False)
    else:
        url = _ask("target URL")
        ns = _ns(tool="gobuster", mode="vhost", wordlist=wl, url=url, domain=None,
                 target=None, port=None, threads=40, extensions=None, status=None,
                 match_codes=None, filter_size=None, user=None, userlist=None,
                 path=None, body=None, fail=None, run=False)
    _emit_and_offer(ns)


# ---- auto-recon for HTTP login forms ------------------------------------ #

LOGIN_PATHS = ["", "/login", "/signin", "/sign-in", "/admin", "/auth/login",
               "/employee/login", "/user/login", "/account/login"]


def _http(url: str, data: dict | None = None, timeout: int = 12,
          cookie: str | None = None, host: str | None = None):
    """GET (data=None) or POST. Returns (status, body, final_url). No redirect follow on POST.
    `host` overrides the Host header (to reach a vhost by IP)."""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"}
    if cookie:
        headers["Cookie"] = cookie
    if host:
        headers["Host"] = host
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body, headers=headers)
    else:
        req = urllib.request.Request(url, headers=headers)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedirect) if data is not None else urllib.request.build_opener()
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        # 302 on a POST is often success; capture it
        return e.code, (e.read().decode("utf-8", "replace") if e.fp else ""), url
    except Exception:
        return None, "", url


def _find_login_form(base_url: str, cookie: str | None = None):
    """Probe common paths for a form containing a password field.
    Returns dict(action, path, user_field, pass_field, page_url) or None."""
    base = base_url.rstrip("/")
    for p in LOGIN_PATHS:
        page_url = base + p
        status, body, _ = _http(page_url, cookie=cookie)
        if status != 200 or "password" not in body.lower():
            continue
        # isolate a <form> block that has a password input
        for m in re.finditer(r"<form\b[^>]*>(.*?)</form>", body, re.S | re.I):
            block = m.group(0)
            if not re.search(r'type=["\']password["\']', block, re.I):
                continue
            action_m = re.search(r'action=["\']([^"\']*)["\']', block, re.I)
            action = action_m.group(1) if action_m else page_url
            action_url = urllib.parse.urljoin(page_url, action or page_url)
            pass_field = re.search(r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\']', block, re.I) \
                or re.search(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']password["\']', block, re.I)
            # username = first non-password/hidden/submit input with a name
            user_field, user_ph = None, ""
            for im in re.finditer(r"<input\b[^>]*>", block, re.I):
                tag = im.group(0)
                t = (re.search(r'type=["\']([^"\']+)["\']', tag, re.I) or [None, "text"])[1].lower()
                nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
                if nm and t not in ("password", "hidden", "submit", "checkbox"):
                    user_field = nm.group(1)
                    ph = re.search(r'placeholder=["\']([^"\']*)["\']', tag, re.I)
                    user_ph = ph.group(1) if ph else ""
                    break
            if pass_field:
                return {
                    "page_url": page_url,
                    "action_url": action_url,
                    "method": (re.search(r'method=["\']([^"\']+)["\']', block, re.I)
                               or [None, "post"])[1].lower(),
                    "path": urllib.parse.urlparse(action_url).path or "/",
                    "user_field": user_field or "username",
                    "user_placeholder": user_ph,
                    "pass_field": pass_field.group(1),
                }
    return None


def _detect_fail_marker(action_url: str, user_field: str, pass_field: str, username: str,
                        cookie: str | None = None):
    """Submit a deliberately wrong password; derive hydra's F= failure marker."""
    status, body, _ = _http(action_url, cookie=cookie,
                            data={user_field: username, pass_field: "wlkit_wrong_pw_zzz"})
    # look for a bootstrap-style alert first, then generic failure words
    alert = re.search(r'class=["\']alert[^"\']*["\'][^>]*>\s*([^<]{3,60})', body, re.I)
    if alert:
        return "F=" + alert.group(1).strip().rstrip("."), status
    for kw in ("invalid credentials", "incorrect password", "login failed",
               "invalid username or password", "authentication failed",
               "wrong password", "access denied", "try again", "invalid", "incorrect"):
        if kw in body.lower():
            # grab the actual-cased phrase from the body
            m = re.search(re.escape(kw), body, re.I)
            return "F=" + body[m.start():m.end()], status
    # nothing obvious -> if a failed POST stays 200 with the form, use a success signal instead
    return None, status


# ---- auto-build a USERNAME list from a site ----------------------------- #

PEOPLE_PATHS = ["", "/about", "/team", "/teams", "/people", "/staff",
                "/careers", "/contact", "/authors", "/company/team"]

# words that look like "First Last" but are really titles/nav/labels, not people
NAME_STOP = {
    "engineer", "engineering", "careers", "career", "portal", "login", "designer",
    "analyst", "specialist", "product", "cloud", "security", "support", "labs",
    "employee", "candidate", "not", "found", "home", "about", "contact", "privacy",
    "terms", "manager", "developer", "senior", "junior", "lead", "team", "sign",
    "log", "read", "learn", "apply", "open", "view", "all", "our", "the", "new",
    "data", "software", "platform", "solutions", "services", "welcome", "dashboard",
    # field labels / nav that pair up as fake "First Last"
    "surname", "nickname", "birthdate", "firstname", "lastname", "first", "last",
    "name", "status", "active", "operations", "details", "actions", "teams",
    "locations", "location", "remote", "search", "benefits", "jobs", "thm",
    "infrastructure", "detection", "feature", "internship", "lab", "full", "ready",
    "find", "settings", "profile", "account", "role", "title", "department",
    "payslips", "payslip", "request", "human", "resources", "time", "hire",
    "hiring", "updated", "edit", "demo", "disabled", "actions", "month", "year",
}


def _scrape_usernames(base_url: str, domain: str | None = None,
                      cookie: str | None = None) -> list[str]:
    """Crawl common people-pages; derive usernames from emails and real names.
    With a session cookie, authenticated pages (e.g. /profile) are reachable too."""
    base = base_url.rstrip("/")
    text_blobs, html_blobs = [], []
    for p in PEOPLE_PATHS + ["/profile", "/account", "/settings", "/me", "/dashboard"]:
        status, body, _ = _http(base + p, cookie=cookie)
        if status == 200 and body:
            html_blobs.append(body)
            text_blobs.append(re.sub(r"<[^>]*>", " ", body))
    allhtml = "\n".join(html_blobs)
    alltext = "\n".join(text_blobs)

    usernames: list[str] = []
    seen = set()

    def add(u: str):
        u = u.strip().lower()
        if u and u not in seen:
            seen.add(u)
            usernames.append(u)

    # 1) emails -> local part is a strong username signal
    for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", allhtml):
        local = email.split("@")[0]
        add(local)
        if "." in local:  # first.last -> also flast, first
            a, b = local.split(".", 1)
            add(a[0] + b)
            add(a)

    # 2) real-looking "First Last" names -> standard username schemes
    names: list[tuple[str, str]] = []
    for a, b in re.findall(r"\b([A-Z][a-z]{1,})\s+([A-Z][a-z]{1,})\b", alltext):
        if a.lower() in NAME_STOP or b.lower() in NAME_STOP:
            continue
        names.append((a.lower(), b.lower()))
    for first, last in dict.fromkeys(names):
        fi = first[0]
        for u in (f"{first}.{last}", f"{first}{last}", f"{fi}{last}",
                  f"{first}{last[0]}", f"{last}{fi}", first, last):
            add(u)

    if domain:
        for u in list(usernames):
            if "@" not in u:
                add(f"{u}@{domain}")
    return usernames


# ---- personal-data mining (names + dates -> CUPP-style candidates) ------ #

# field labels / UI / page-chrome words that aren't personal values
PERSONAL_STOP = {
    "first", "name", "surname", "last", "nickname", "birthdate", "employee",
    "details", "status", "active", "operations", "department", "role", "title",
    "email", "phone", "address", "profile", "account", "settings", "dashboard",
    "edit", "view", "request", "payslips", "time", "off", "sign", "out", "home",
    "last", "updated", "today", "ddmmyyyy", "mmddyyyy", "yyyy", "the", "and",
    # page chrome that appears on profile pages but isn't personal
    "engineering", "careers", "career", "actions", "action", "demo", "disabled",
    "lab", "labs", "jobs", "thm", "teams", "team", "locations", "location",
    "benefits", "candidate", "portal", "login", "logout", "senior", "junior",
    "remote", "search", "infrastructure", "detection", "feature", "internship",
    "find", "ready", "full", "design", "engineer", "apply", "welcome", "toast",
}


def _norm_year(y: str) -> str:
    """2-digit year -> 4-digit (heuristic: >30 => 19xx else 20xx)."""
    if len(y) == 4:
        return y
    return ("19" if int(y) > 30 else "20") + y


def _add_date(frags: set, d: str, mo: str, y: str):
    d2, m2 = d.zfill(2), mo.zfill(2)
    y4 = _norm_year(y)
    y2 = y4[2:]
    for f in (y4, y2, d2 + m2, m2 + d2, d2 + m2 + y4, d2 + m2 + y2,
              y4 + m2 + d2, d2, m2, d.lstrip("0"), y4 + m2, m2 + y4):
        if f:
            frags.add(f)


def _date_fragments(text: str) -> set:
    """Pull dates/birthdates from text and derive useful password fragments."""
    frags: set = set()
    # separated: 14/02/1995, 14-2-95, 14.02.1995
    for d, mo, y in re.findall(r"\b(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{2,4})\b", text):
        if 1 <= int(d) <= 31 and 1 <= int(mo) <= 12:
            _add_date(frags, d, mo, y)
    # compact 8-digit: DDMMYYYY or YYYYMMDD
    for s in re.findall(r"\b(\d{8})\b", text):
        frags.add(s)
        d, mo, y = s[0:2], s[2:4], s[4:8]
        if 1 <= int(d) <= 31 and 1 <= int(mo) <= 12 and 1900 <= int(y) <= 2100:
            _add_date(frags, d, mo, y)
        y2, mo2, d2 = s[0:4], s[4:6], s[6:8]
        if 1900 <= int(y2) <= 2100 and 1 <= int(mo2) <= 12 and 1 <= int(d2) <= 31:
            _add_date(frags, d2, mo2, y2)
    # 6-digit DDMMYY
    for s in re.findall(r"\b(\d{6})\b", text):
        frags.add(s)
    # standalone years
    for y in re.findall(r"\b(19\d{2}|20\d{2})\b", text):
        frags.add(y)
        frags.add(y[2:])
    return frags


def _mine_personal(text: str) -> tuple[list[str], set, list[str]]:
    """From page text, return (ranked_candidate_passwords, date_fragments, name_words).
    Candidates are ordered most-likely-first: name alone, name+year, name+full
    birthdate, then partial dates, then suffixes/leet, then raw dates."""
    names: list[str] = []
    for w in re.findall(r"[A-Za-z][A-Za-z']{2,}", text):
        if w.lower() in PERSONAL_STOP:
            continue
        if w not in names:
            names.append(w)
    dates = _date_fragments(text)

    # classify date fragments by how "strong" a password suffix they are
    years4 = sorted({d for d in dates if re.fullmatch(r"(19|20)\d{2}", d)}, reverse=True)
    fulls = sorted({d for d in dates if len(d) == 8})          # DDMMYYYY / YYYYMMDD
    sixes = sorted({d for d in dates if len(d) == 6})          # DDMMYY
    mid = sorted({d for d in dates if len(d) == 4 and d not in years4})  # DDMM/MMDD
    small = sorted({d for d in dates if len(d) <= 2})          # DD, MM, YY-ish

    ordered: list[str] = []
    seen: set = set()

    def push(w: str):
        if w and 3 <= len(w) <= 32 and w not in seen:
            seen.add(w)
            ordered.append(w)

    # case variants of a name, most natural first
    def variants(w):
        return [w.lower(), w.capitalize(), w, w.upper()]

    # tier 1: the name/nickname itself
    for w in names:
        for v in variants(w):
            push(v)
    # tier 2: name + full 4-digit year (the single most common pattern)
    for w in names:
        for v in variants(w):
            for y in years4:
                push(v + y)
    # tier 3: name + full birthdate / DDMMYY
    for w in names:
        for v in variants(w):
            for d in fulls + sixes:
                push(v + d)
    # tier 4: name + partial (DDMM) and short bits, plus date-prefix forms
    for w in names:
        for v in variants(w):
            for d in mid + small:
                push(v + d)
            for y in years4:
                push(y + v)
    # tier 5: name + symbol/number suffixes
    for w in names:
        for v in variants(w):
            for s in ("!", "@", "#", "$", "123", "1", "01", "007", "!!", "123!"):
                push(v + s)
    # tier 6: leetspeak of name (+ year)
    for w in names:
        leetv = "".join(LEET_MAP.get(c, c) for c in w.lower())
        if leetv != w.lower():
            push(leetv)
            for y in years4:
                push(leetv + y)
            for d in fulls:
                push(leetv + d)
    # tier 7: raw dates on their own (e.g. 14021995)
    for d in fulls + sixes + years4 + mid:
        push(d)

    return ordered, dates, names


def _scrape_personal(url: str, cookie: str | None):
    """Fetch a (usually authenticated) page and mine personal-data passwords from it.
    Strips <script>/<style> so CSS/JS identifiers don't pollute the name list."""
    _status, body, _ = _http(url, cookie=cookie)
    body = re.sub(r"<script.*?</script>", " ", body, flags=re.S | re.I)
    body = re.sub(r"<style.*?</style>", " ", body, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", body)
    text = html.unescape(text)
    return _mine_personal(text)


# ---- login brute (build custom list, then hydra) ------------------------ #

def _wizard_build_list(default_name: str, default_scrape: str = "") -> str:
    """Menu-driven wordlist construction. Returns the path written."""
    src = _menu(
        "How should I build the wordlist?",
        [
            ("scrape",   "CeWL-style: pull words off a saved page / text file"),
            ("profile",  "CUPP-style: from names/dates/keywords you give me"),
            ("both",     "scrape + profile, merged"),
            ("existing", "use a list I already have (path)"),
            ("rockyou",  "use rockyou.txt as-is"),
        ],
    )
    out_dir = _wl_dir()
    pieces: list[str] = []

    if src == "rockyou":
        return "/usr/share/wordlists/rockyou.txt"
    if src == "existing":
        return _ask("path to your wordlist")

    if src in ("scrape", "both"):
        src_file = _ask("URL to fetch (http://...) or path to a saved page/text file",
                        default_scrape or None)
        cookie = None
        if re.match(r"^https?://", src_file, re.I) and \
                _yesno("does the page need login (send a session cookie)?", False):
            cookie = _ask("paste Cookie header (e.g. session=...; jobs_authed=1)") or None
        raw = str(out_dir / "_scrape_raw.txt")
        ns = _ns(input=src_file, strip_html=_yesno("strip HTML tags first?", True),
                 min_length=4, max_length=32, lowercase=False, sort=False, output=raw,
                 cookie=cookie)
        cmd_extract(ns)
        pieces.append(raw)

    if src in ("profile", "both"):
        words = _ask("seed terms (names, years, keywords - space separated)")
        pet = _ask("pet / extra keyword (blank to skip)", "")
        ns = _ns(words=[words] if words else [], pet=[pet] if pet else None,
                 combine=True, leet=_yesno("add leetspeak variants?", True),
                 years_back=40, min_length=6, max_length=24,
                 output=str(out_dir / "_profile.txt"))
        cmd_profile(ns)
        pieces.append(str(out_dir / "_profile.txt"))

    # merge (if both) then optional mutation
    merged = str(out_dir / default_name)
    if len(pieces) > 1:
        ns = _ns(inputs=pieces, sort=False, by_frequency=True, output=merged)
        cmd_combine(ns)
    else:
        # single source -> optionally mutate it into the final file
        base = pieces[0]
        if _yesno("apply mutation rules (case/leet/append years+numbers)?", True):
            ns = _ns(input=base, case=True, leet=True, append=True, prepend=False,
                     years_back=15, min_length=1, max_length=32, output=merged)
            cmd_mutate(ns)
        else:
            Path(merged).write_text(Path(base).read_text(encoding="utf-8", errors="replace"))
    return merged


def _wizard_login():
    svc = _menu("What are we attacking?",
                [("http-post-form", "web login form (POST)"),
                 ("http-get-form", "web login form (GET)"),
                 ("ssh", "SSH"), ("ftp", "FTP"), ("smb", "SMB"),
                 ("mysql", "MySQL"), ("postgres", "PostgreSQL")])

    is_web = svc in ("http-post-form", "http-get-form")
    target = port = path = body = fail = None
    scrape_hint = ""

    # ---- auto-recon for web logins ------------------------------------- #
    if is_web:
        base_url = _ask("target base URL (e.g. http://10.49.152.19:5002)")
        scrape_hint = base_url
        parsed = urllib.parse.urlparse(base_url)
        target = parsed.hostname or base_url
        port = str(parsed.port or (443 if parsed.scheme == "https" else 80))

        print("  [*] probing for a login form ...")
        form = _find_login_form(base_url)
        if form:
            path = form["path"]
            body = f"{form['user_field']}=^USER^&{form['pass_field']}=^PASS^"
            print(f"  [+] found form at {form['path']} "
                  f"(fields: {form['user_field']} / {form['pass_field']})")
        else:
            print("  [!] couldn't auto-find the form - I'll ask you.")
            path = _ask("form path (e.g. /login)")
            uf = _ask("username field name", "username")
            pf = _ask("password field name", "password")
            body = f"{uf}=^USER^&{pf}=^PASS^"

    # ---- username --------------------------------------------------------- #
    user = userlist = None
    usrc = _menu(
        "Username source?",
        [
            ("single",  "I know one username"),
            ("scrape",  "auto-build a list from a site (names/emails)"),
            ("file",    "use a username list file I already have"),
        ],
    )
    if usrc == "single":
        user = _ask("username")
    elif usrc == "file":
        userlist = _ask("path to username list")
    else:  # scrape usernames from a link
        u_url = _ask("site URL to scrape names/emails from", scrape_hint or None)
        dom = _ask("email domain to append (blank = none)", "")
        print("  [*] scraping people/team/about pages for usernames ...")
        users = _scrape_usernames(u_url, dom or None)
        userlist = str(_wl_dir() / "usernames.txt")
        write_lines(users, userlist)
        print(f"  [+] {len(users)} username(s) -> {userlist}")
        if users:
            print("      e.g. " + ", ".join(users[:8]))
        else:
            print("  [!] no names/emails found on that site.")
            if _yesno("fall back to a single username?", True):
                user, userlist = _ask("username"), None

    # ---- detect failure marker (needs a username to test with) ---------- #
    if is_web:
        probe_user = user or "admin"
        uf, pf = body.split("=^USER^&")[0], body.split("&")[1].split("=^PASS^")[0]
        print("  [*] detecting failure marker (one test login) ...")
        action_url = urllib.parse.urljoin(scrape_hint.rstrip("/") + "/", path.lstrip("/"))
        marker, _ = _detect_fail_marker(action_url, uf, pf, probe_user)
        if marker:
            fail = marker
            print(f"  [+] failure marker: {fail}")
        else:
            fail = _ask("failure marker (e.g. F=Invalid credentials)", "F=Invalid")

    # ---- build the password list --------------------------------------- #
    print("\n-- Building the password list --")
    wl = _wizard_build_list("login_wordlist.txt", default_scrape=scrape_hint)
    print(f"\n[+] Password list: {wl}")

    # ---- non-web target details ---------------------------------------- #
    if not is_web:
        target = _ask("host / IP (e.g. 10.49.152.19)")
        port = _ask("port", {"ssh": "22", "ftp": "21", "smb": "445",
                             "mysql": "3306", "postgres": "5432"}.get(svc, ""))

    # SSH/FTP throttle: 4 threads is the safe standard; web forms tolerate more
    threads = 4 if svc in ("ssh", "ftp") else 16

    ns = _ns(tool="hydra", mode=svc, wordlist=wl, url=None, domain=None,
             target=target, port=int(port) if str(port).isdigit() else None,
             threads=threads, extensions=None, status=None, match_codes=None,
             filter_size=None, user=user, userlist=userlist, path=path,
             body=body, fail=fail, run=False)
    _emit_and_offer(ns)


# ---- shared: print command, offer to run -------------------------------- #

def _emit_and_offer(ns):
    cmd = _build_command(ns)
    printable = " ".join(shlex.quote(c) for c in cmd)
    print("\n" + "=" * 64)
    print("Command:")
    print("  " + printable)
    print("=" * 64)
    if _yesno("run it now?", False):
        print("[wlkit] authorised targets only.")
        if _ask("type 'yes' to execute").lower() == "yes":
            try:
                subprocess.run(cmd)
            except FileNotFoundError:
                print(f"[wlkit] '{cmd[0]}' not installed or not in PATH.")
        else:
            print("[wlkit] not executed.")


# --------------------------------------------------------------------------- #
# cupp  (faithful port of Mebus/cupp generate_wordlist_from_profile)
# --------------------------------------------------------------------------- #

# defaults mirror cupp.cfg exactly (incl. cupp's literal "'#'" quirk)
CUPP_CFG = {
    "years": [str(y) for y in range(1990, 2023)],
    "chars": ["!", "@", "'#'", "$", "%", "&", "*"],
    "numfrom": 0,
    "numto": 100,
    "wcfrom": 5,      # cupp keeps words with wcfrom < len < wcto
    "wcto": 12,
    "leet": {"a": "4", "i": "1", "e": "3", "t": "7", "o": "0", "s": "5",
             "g": "9", "z": "2"},
}


def _cupp_leet(x: str, leet: dict) -> str:
    for letter, sub in leet.items():
        x = x.replace(letter, sub)
    return x


def _cupp_concats(seq, start, stop):
    for s in seq:
        for num in range(start, stop):
            yield s + str(num)


def _cupp_komb(seq, start, special=""):
    for a in seq:
        for b in start:
            yield a + special + b


def _cupp_bdss(bd: str) -> list:
    """Replicate cupp's birthday-fragment expansion (1/2/3-part combos)."""
    parts = [bd[-2:], bd[-3:], bd[-4:], bd[1:2], bd[3:4], bd[:2], bd[2:4]]
    out = []
    for i, p1 in enumerate(parts):
        out.append(p1)
        for j, p2 in enumerate(parts):
            if i != j:
                out.append(p1 + p2)
                for k, p3 in enumerate(parts):
                    if i != j and j != k and i != k:
                        out.append(p1 + p2 + p3)
    return out


def _cupp_pairs(seq: list) -> list:
    """cupp's self-concatenation of a name group. Uses cupp's exact guard
    (list.index on the value and on its .title()) so case-variants of the same
    word are not concatenated with each other (e.g. no 'marcoMarco')."""
    out = []
    for a in seq:
        out.append(a)
        for b in seq:
            if seq.index(a) != seq.index(b) and \
                    seq.index(a.title()) != seq.index(b.title()):
                out.append(a + b)
    return out


def _cupp_generate(p: dict, cfg: dict) -> list:
    """Port of cupp.generate_wordlist_from_profile. p has cupp profile keys."""
    chars, years = cfg["chars"], cfg["years"]
    numfrom, numto = cfg["numfrom"], cfg["numto"]

    spechars = []
    if p.get("spechars1") == "y":
        for s1 in chars:
            spechars.append(s1)
            for s2 in chars:
                spechars.append(s1 + s2)
                for s3 in chars:
                    spechars.append(s1 + s2 + s3)

    nameup, surnameup, nickup = p["name"].title(), p["surname"].title(), p["nick"].title()
    wifeup, wifenup = p["wife"].title(), p["wifen"].title()
    kidup, kidnup = p["kid"].title(), p["kidn"].title()
    petup, companyup = p["pet"].title(), p["company"].title()

    base_words = p["words"] or [""]        # cupp baseline is [""], not empty
    wordsup = list(map(str.title, base_words))
    word = base_words + wordsup

    rev_name, rev_nameup = p["name"][::-1], nameup[::-1]
    rev_nick, rev_nickup = p["nick"][::-1], nickup[::-1]
    rev_wife, rev_wifeup = p["wife"][::-1], wifeup[::-1]
    rev_kid, rev_kidup = p["kid"][::-1], kidup[::-1]
    reverse = [rev_name, rev_nameup, rev_nick, rev_nickup,
               rev_wife, rev_wifeup, rev_kid, rev_kidup]
    rev_n = [rev_name, rev_nameup, rev_nick, rev_nickup]
    rev_w = [rev_wife, rev_wifeup]
    rev_k = [rev_kid, rev_kidup]

    bdss = _cupp_bdss(p["birthdate"])
    wbdss = _cupp_bdss(p["wifeb"])
    kbdss = _cupp_bdss(p["kidb"])

    kombinaac = [p["pet"], petup, p["company"], companyup]
    kombina = [p["name"], p["surname"], p["nick"], nameup, surnameup, nickup]
    kombinaw = [p["wife"], p["wifen"], wifeup, wifenup, p["surname"], surnameup]
    kombinak = [p["kid"], p["kidn"], kidup, kidnup, p["surname"], surnameup]

    kombinaa = _cupp_pairs(kombina)
    kombinaaw = _cupp_pairs(kombinaw)
    kombinaak = _cupp_pairs(kombinak)

    K = _cupp_komb
    kombi = {}
    kombi[1] = list(K(kombinaa, bdss)) + list(K(kombinaa, bdss, "_"))
    kombi[2] = list(K(kombinaaw, wbdss)) + list(K(kombinaaw, wbdss, "_"))
    kombi[3] = list(K(kombinaak, kbdss)) + list(K(kombinaak, kbdss, "_"))
    kombi[4] = list(K(kombinaa, years)) + list(K(kombinaa, years, "_"))
    kombi[5] = list(K(kombinaac, years)) + list(K(kombinaac, years, "_"))
    kombi[6] = list(K(kombinaaw, years)) + list(K(kombinaaw, years, "_"))
    kombi[7] = list(K(kombinaak, years)) + list(K(kombinaak, years, "_"))
    kombi[8] = list(K(word, bdss)) + list(K(word, bdss, "_"))
    kombi[9] = list(K(word, wbdss)) + list(K(word, wbdss, "_"))
    kombi[10] = list(K(word, kbdss)) + list(K(word, kbdss, "_"))
    kombi[11] = list(K(word, years)) + list(K(word, years, "_"))
    for i in (12, 13, 14, 15, 16, 21):
        kombi[i] = [""]
    if p.get("randnum") == "y":
        kombi[12] = list(_cupp_concats(word, numfrom, numto))
        kombi[13] = list(_cupp_concats(kombinaa, numfrom, numto))
        kombi[14] = list(_cupp_concats(kombinaac, numfrom, numto))
        kombi[15] = list(_cupp_concats(kombinaaw, numfrom, numto))
        kombi[16] = list(_cupp_concats(kombinaak, numfrom, numto))
        kombi[21] = list(_cupp_concats(reverse, numfrom, numto))
    kombi[17] = list(K(reverse, years)) + list(K(reverse, years, "_"))
    kombi[18] = list(K(rev_w, wbdss)) + list(K(rev_w, wbdss, "_"))
    kombi[19] = list(K(rev_k, kbdss)) + list(K(rev_k, kbdss, "_"))
    kombi[20] = list(K(rev_n, bdss)) + list(K(rev_n, bdss, "_"))

    komb001 = komb002 = komb003 = komb004 = komb005 = komb006 = [""]
    if spechars:
        komb001 = list(K(kombinaa, spechars))
        komb002 = list(K(kombinaac, spechars))
        komb003 = list(K(kombinaaw, spechars))
        komb004 = list(K(kombinaak, spechars))
        komb005 = list(K(word, spechars))
        komb006 = list(K(reverse, spechars))

    def uniq(seq):
        return list(dict.fromkeys(seq).keys())

    uniqlist = (bdss + wbdss + kbdss + reverse
                + uniq(kombinaa) + uniq(kombinaac) + uniq(kombinaaw)
                + uniq(kombinaak) + uniq(word))
    for i in range(1, 21):
        uniqlist += uniq(kombi[i])
    uniqlist += (uniq(komb001) + uniq(komb002) + uniq(komb003)
                 + uniq(komb004) + uniq(komb005) + uniq(komb006))

    unique_lista = uniq(uniqlist)
    if p.get("leetmode") == "y":
        unique_lista = unique_lista + [_cupp_leet(x, cfg["leet"]) for x in unique_lista]

    wcfrom, wcto = cfg["wcfrom"], cfg["wcto"]
    return [x for x in unique_lista if wcfrom < len(x) < wcto]


def _cupp_profile_from_url(url: str, cookie: str | None) -> dict:
    """Auto-fill a cupp profile from an (authenticated) profile page."""
    _s, body, _u = _http(url, cookie=cookie)
    body = re.sub(r"<script.*?</script>|<style.*?</style>", " ", body, flags=re.S | re.I)
    text = html.unescape(re.sub(r"<[^>]+>", " ", body))
    text = re.sub(r"\s+", " ", text)

    def grab(label):
        m = re.search(label + r"\s*[:\-]?\s*([A-Za-z][A-Za-z'\-]{1,30})", text, re.I)
        return m.group(1).lower() if m else ""

    name = grab(r"First ?Name") or grab(r"\bName\b")
    surname = grab(r"Surname") or grab(r"Last ?Name")
    nick = grab(r"Nick ?name")
    bd = re.search(r"\b(\d{8})\b", text)
    birthdate = bd.group(1) if bd else ""
    return {"name": name, "surname": surname, "nick": nick, "birthdate": birthdate}


def cmd_cupp(args):
    cfg = dict(CUPP_CFG)
    if args.years:
        cfg["years"] = [y.strip() for y in args.years.split(",") if y.strip()]
    cfg["wcfrom"], cfg["wcto"] = args.wcfrom, args.wcto
    cfg["numfrom"], cfg["numto"] = args.numfrom, args.numto

    # blank cupp profile
    p = {k: "" for k in ("name", "surname", "nick", "birthdate", "wife", "wifen",
                         "wifeb", "kid", "kidn", "kidb", "pet", "company")}
    p["words"] = []
    p["spechars1"] = "y" if args.special else "n"
    p["randnum"] = "y" if args.randnum else "n"
    p["leetmode"] = "y" if args.leet else "n"

    if args.from_url:
        got = _cupp_profile_from_url(args.from_url, args.cookie)
        p.update({k: v for k, v in got.items() if v})
        sys.stderr.write(f"[cupp] profile from {args.from_url}: "
                         f"name={p['name']!r} surname={p['surname']!r} "
                         f"nick={p['nick']!r} birthdate={p['birthdate']!r}\n")
    elif args.interactive:
        print("[ cupp interactive profiler ]  (blank = skip)")
        p["name"] = _ask("First Name").lower()
        p["surname"] = _ask("Surname").lower()
        p["nick"] = _ask("Nickname").lower()
        p["birthdate"] = _ask("Birthdate (DDMMYYYY)")
        if _yesno("add info about partner?", False):
            p["wife"] = _ask("  partner name").lower()
            p["wifen"] = _ask("  partner nickname").lower()
            p["wifeb"] = _ask("  partner birthdate (DDMMYYYY)")
        if _yesno("add info about child?", False):
            p["kid"] = _ask("  child name").lower()
            p["kidn"] = _ask("  child nickname").lower()
            p["kidb"] = _ask("  child birthdate (DDMMYYYY)")
        p["pet"] = _ask("Pet's name").lower()
        p["company"] = _ask("Company name").lower()
        kw = _ask("keywords (comma separated)")
        p["words"] = [w.strip() for w in kw.split(",") if w.strip()]
        p["spechars1"] = "y" if _yesno("add special chars at the end?", False) else "n"
        p["randnum"] = "y" if _yesno("add random numbers at the end?", False) else "n"
        p["leetmode"] = "y" if _yesno("leet mode?", False) else "n"
    else:
        p["name"] = (args.name or "").lower()
        p["surname"] = (args.surname or "").lower()
        p["nick"] = (args.nick or "").lower()
        p["birthdate"] = args.birthdate or ""
        p["wife"] = (args.wife or "").lower()
        p["wifen"] = (args.wifen or "").lower()
        p["wifeb"] = args.wifeb or ""
        p["kid"] = (args.kid or "").lower()
        p["kidn"] = (args.kidn or "").lower()
        p["kidb"] = args.kidb or ""
        p["pet"] = (args.pet or "").lower()
        p["company"] = (args.company or "").lower()
        if args.words:
            p["words"] = [w.strip() for w in re.split(r"[,\s]+", " ".join(args.words)) if w.strip()]

    if not any([p["name"], p["surname"], p["nick"], p["words"]]):
        sys.exit("[cupp] need at least a name/nick/surname or keywords "
                 "(use --interactive, --from-url, or --name ...)")

    result = _cupp_generate(p, cfg)
    out = args.output or ((p["name"] or "cupp") + ".txt")
    write_lines(result, out)
    sys.stderr.write(f"[cupp] {len(result)} words -> {out}\n")



# --------------------------------------------------------------------------- #
# osint  (people/keywords from imports or a public page -> strong wordlist)
# --------------------------------------------------------------------------- #
#
# Ingests OSINT the tester already has (a file / inline names) or a public page,
# and builds a ranked, target-specific wordlist with the CUPP + template engines.
# It does NOT log into or scrape any ToS-protected platform (LinkedIn, etc.).

def _split_name(full: str):
    """'John Smith' / 'john.smith' -> (first, last)."""
    parts = [p for p in re.split(r"[\s._-]+", full.strip()) if p]
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0].lower(), ""
    return parts[0].lower(), parts[-1].lower()


def _people_from_text(text: str):
    """Pull (people, keywords) out of arbitrary OSINT text/CSV.
    people = [{name, surname, nick, birthdate}], keywords = [str]."""
    people, seen_people = [], set()
    keywords, seen_kw = [], set()

    def add_person(first, last, nick="", bd=""):
        key = (first, last, nick)
        if any(key) and key not in seen_people:
            seen_people.add(key)
            people.append({"name": first, "surname": last, "nick": nick, "birthdate": bd})

    def add_kw(w):
        w = w.strip().lower()
        if w and re.fullmatch(r"[a-z][a-z0-9]{2,}", w) and w not in seen_kw \
                and w not in NAME_STOP and not re.fullmatch(r"[0-9a-f]{3,8}", w):
            seen_kw.add(w)
            keywords.append(w)

    # emails -> strong name signal
    for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        local = email.split("@")[0]
        f, l = _split_name(local)
        add_person(f, l, nick=(local.lower() if "." not in local else ""))

    # 'First Last' names (filtered against the nav/label stoplist)
    for a, b in re.findall(r"\b([A-Z][a-z]{1,})\s+([A-Z][a-z]{1,})\b", text):
        if a.lower() not in NAME_STOP and b.lower() not in NAME_STOP:
            add_person(a.lower(), b.lower())

    # dates (birthdays) - attach loosely as extra fragments via keywords engine later
    return people, keywords


_KW_STOP = {
    "the", "and", "for", "with", "from", "that", "this", "location", "about",
    "skills", "skill", "interests", "interest", "experience", "education", "summary",
    "present", "current", "years", "year", "month", "months", "company", "role",
    "title", "team", "profile", "linkedin", "connections", "followers", "contact",
    "www", "http", "https", "com", "http", "email", "phone", "address", "university",
    "college", "school", "bachelor", "master", "degree", "certificate", "certified",
    "member", "since", "view", "more", "less", "show", "all", "see", "add", "message",
}


def _profile_keywords(text: str) -> list[str]:
    """Pull useful seed keywords from a profile export: labeled lists (skills,
    interests, tools, languages) first, then other notable words."""
    kws, seen = [], set()

    def add(w):
        w = w.strip().lower()
        if (w and 3 <= len(w) <= 18 and re.fullmatch(r"[a-z][a-z0-9]+", w)
                and w not in seen and w not in _KW_STOP
                and w not in NAME_STOP and w not in PERSONAL_STOP):
            seen.add(w)
            kws.append(w)

    # labeled comma/slash lists (skills, interests, tools, languages, technologies)
    for m in re.finditer(r"(?:skills?|interests?|hobb(?:y|ies)|tools?|languages?|"
                         r"technolog\w*|expertise|focus)\s*[:\-]\s*([^\n]+)", text, re.I):
        for item in re.split(r"[,/;|]", m.group(1)):
            for w in re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", item):
                add(w)
    # remaining notable words (kept moderate; stoplist prunes the boilerplate)
    for w in re.findall(r"[A-Za-z][A-Za-z0-9]{3,15}", text):
        add(w)
    return kws


def _try_harvester_json(txt: str):
    """If `txt` is theHarvester JSON output, parse it. Returns
    (people, keywords, emails, hosts, names) or None if it isn't that format."""
    s = txt.strip()
    if not s.startswith("{"):
        return None
    try:
        data = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or not any(
            k in data for k in ("emails", "hosts", "ips", "linkedin_people")):
        return None

    def arr(*keys):
        for k in keys:
            v = data.get(k)
            if isinstance(v, list) and v:
                return v
        return []

    emails = sorted({e.strip().lower() for e in arr("emails") if e and "@" in e})
    hosts = sorted({str(h).split(":")[0].strip().lower() for h in arr("hosts") if h})
    names = [p for p in arr("linkedin_people", "people", "linkedin") if p and " " in p]

    people, seen = [], set()
    def add_person(f, l, nick=""):
        key = (f, l, nick)
        if any(key) and key not in seen:
            seen.add(key)
            people.append({"name": f, "surname": l, "nick": nick, "birthdate": ""})
    for e in emails:
        local = e.split("@")[0]
        f, l = _split_name(local)
        add_person(f, l, nick=(local if "." not in local else ""))
    for nm in names:
        f, l = _split_name(nm)
        add_person(f, l)

    # subdomain labels are strong keywords (brand/product/app words)
    keywords, kseen = [], set()
    def add_kw(w):
        w = w.strip().lower()
        if (w and re.fullmatch(r"[a-z][a-z0-9]{2,}", w) and w not in kseen
                and w not in NAME_STOP and not re.fullmatch(r"[0-9a-f]{3,8}", w)):
            kseen.add(w); keywords.append(w)
    for h in hosts:
        for label in h.split(".")[:-2]:      # drop the registrable domain + TLD
            for part in re.split(r"[-_]", label):
                add_kw(part)
    return people, keywords, emails, hosts, names


def cmd_osint(args):
    cmd_osint._osint_emails = []
    cmd_osint._osint_names = []
    people, keywords = [], list(args.keywords or [])
    dates: set = set()

    # ---- gather sources ------------------------------------------------- #
    if args.names:
        for nm in re.split(r"[,;]", " ".join(args.names)):
            f, l = _split_name(nm)
            if f:
                people.append({"name": f, "surname": l, "nick": "", "birthdate": ""})

    if args.import_file:
        txt = Path(args.import_file).read_text(encoding="utf-8", errors="replace")
        hv = _try_harvester_json(txt)
        if hv is not None:               # native theHarvester JSON
            p, k, emails, hosts, names = hv
            people += p
            keywords += k
            dates |= _date_fragments(" ".join(emails + names))
            cmd_osint._osint_emails = emails      # stash for optional --users output
            cmd_osint._osint_names = names
            sys.stderr.write(f"[osint] theHarvester JSON {args.import_file}: "
                             f"{len(emails)} emails, {len(hosts)} subdomains, "
                             f"{len(names)} names -> {len(p)} people, {len(k)} keywords\n")
        else:                            # plain text / CSV / profile export
            p, k = _people_from_text(txt)
            k += _profile_keywords(txt)
            people += p
            keywords += k
            dates |= _date_fragments(txt)
            sys.stderr.write(f"[osint] import {args.import_file}: "
                             f"{len(p)} people, {len(dict.fromkeys(k))} keywords\n")

    if args.from_url:
        status, body, _u = _http(args.from_url, cookie=args.cookie, host=args.host)
        dom = urllib.parse.urlparse(args.from_url).hostname or ""
        blocked = any(d in dom for d in ("linkedin.", "facebook.", "instagram.",
                                         "twitter.", "x.com"))
        if not body:
            msg = [f"[osint] could not fetch {args.from_url} "
                   f"(HTTP {status if status is not None else 'no response / blocked / timeout'})."]
            if blocked:
                msg.append("        LinkedIn/social sites block automated fetches AND "
                           "render profiles with JavaScript, so a plain GET returns "
                           "nothing usable - a cookie won't change that, and automating "
                           "with your session risks the account.")
                msg.append("        Do this instead: open your own profile in the browser, "
                           "'... More -> Save to PDF' (or Settings -> Get a copy of your "
                           "data), then feed that file:")
                msg.append("          wlkit osint --import kanishk_profile.pdf.txt "
                           "--company <employer> -o kanishk.txt")
                msg.append("        (convert the PDF to text first: `pdftotext file.pdf "
                           "file.txt`, then --import the .txt)")
            else:
                msg.append("        Check the URL, --cookie, and --host. If the page is "
                           "JavaScript-rendered, save it from the browser and use --import.")
            sys.stderr.write("\n".join(msg) + "\n")
            if not (args.names or args.import_file or args.company or args.keywords):
                sys.exit(1)
            sys.stderr.write("[osint] continuing with the other sources you gave.\n")
        else:
            clean = re.sub(r"<script.*?</script>|<style.*?</style>", " ", body, flags=re.S | re.I)
            text = html.unescape(re.sub(r"<[^>]+>", " ", clean))
            p, _k = _people_from_text(text)
            kws = _keywords_from_body(body)
            if blocked and not p and not kws:
                sys.stderr.write(
                    f"[osint] fetched {len(body)} bytes from {dom} but found no profile "
                    "data - LinkedIn/social pages are JavaScript-rendered, so the useful "
                    "fields aren't in the HTML.\n"
                    "        Export your own profile instead and --import it:\n"
                    "          browser -> your profile -> More -> Save to PDF\n"
                    "          pdftotext profile.pdf profile.txt\n"
                    "          wlkit osint --import profile.txt --company <employer> -o out.txt\n")
            people += p
            keywords += kws
            dates |= _date_fragments(text)
            sys.stderr.write(f"[osint] {args.from_url}: {len(p)} people, "
                             f"{len(kws)} tag-keywords\n")

    if args.company:
        keywords.insert(0, args.company.lower())

    # dedupe
    keywords = list(dict.fromkeys([k for k in keywords if k]))
    uniq_people, seenp = [], set()
    for p in people:
        key = (p["name"], p["surname"], p["nick"])
        if any(key) and key not in seenp:
            seenp.add(key); uniq_people.append(p)
    people = uniq_people

    if not people and not keywords:
        sys.exit("[osint] nothing to work with. Give --names, --import, --from-url, "
                 "--company, or --keywords.")

    sys.stderr.write(f"[osint] building from {len(people)} people + "
                     f"{len(keywords)} keywords\n")

    # ---- generate a ranked wordlist ------------------------------------- #
    this_year = datetime.now().year
    years = [str(y) for y in range(this_year - 6, this_year + 1)]
    syms = ["!", "@", "#", "$"]
    nums = [str(i) for i in range(0, 101)] if args.big else \
        ["1", "12", "123", "01", "007", "2", "3", "00", "69"]

    seen, out = set(), []
    def add(w):
        if w and 3 <= len(w) <= 40 and w not in seen:
            seen.add(w); out.append(w)

    # tier 1: company/keywords, capitalized + year + ! (the strongest human pattern)
    kw_all = keywords + [k.capitalize() for k in keywords]
    for kw in keywords:
        for v in {kw, kw.capitalize(), kw.upper()}:
            add(v)
    for kw in keywords:
        for tmpl in ("{cap}{year}!", "{cap}{year}", "{cap}{num}!"):
            for cand in _apply_template(kw, tmpl, years, syms, nums):
                add(cand)
    for kw in keywords:
        for s in syms:
            add(kw.capitalize() + s)

    # tier 2: per-person CUPP (faithful engine) - name/surname/nick + company + kws
    cfg = dict(CUPP_CFG)
    cfg["years"] = years
    for p in people:
        prof = {k: "" for k in ("name", "surname", "nick", "birthdate", "wife",
                                "wifen", "wifeb", "kid", "kidn", "kidb", "pet", "company")}
        prof.update({"name": p["name"], "surname": p["surname"], "nick": p["nick"],
                     "birthdate": p["birthdate"], "company": args.company or ""})
        prof["words"] = keywords
        prof["spechars1"] = "y" if args.deep else "n"
        prof["randnum"] = "y" if args.deep else "n"
        prof["leetmode"] = "y" if args.leet else "n"
        for w in _cupp_generate(prof, cfg):
            add(w)

    # tier 3: name x loose dates found in the source (birthdays not tied to a person)
    if dates:
        for p in people:
            for base in {p["name"], p["name"].capitalize(), p["nick"]}:
                if not base:
                    continue
                for d in sorted(dates):
                    add(base + d)

    write_lines(out, args.output)
    sys.stderr.write(f"[osint] {len(out)} candidates -> {args.output}\n")
    if out:
        sys.stderr.write("         top: " + ", ".join(out[:8]) + "\n")

    # optional: derive a usernames file from emails/names (e.g. theHarvester import)
    if getattr(args, "users", None):
        seenu, users = set(), []
        def addu(u):
            u = u.strip().lower()
            if u and u not in seenu:
                seenu.add(u); users.append(u)
        for e in cmd_osint._osint_emails:
            local = e.split("@")[0]; addu(local)
            if "." in local:
                a, b = local.split(".", 1); addu(a[0] + b); addu(a)
        for p in people:
            f, l = p["name"], p["surname"]
            if f and l:
                addu(f"{f}.{l}"); addu(f"{f}{l}"); addu(f[0] + l); addu(f); addu(l)
        write_lines(users, args.users)
        sys.stderr.write(f"[osint] {len(users)} usernames -> {args.users}\n")


# --------------------------------------------------------------------------- #
# harvest  (URL [+cookie] -> users.txt + passwords.txt)
# --------------------------------------------------------------------------- #

def cmd_harvest(args):
    """Scrape a site (optionally authenticated) into a username list AND a
    password list (personal-data CUPP candidates + mutated site keywords)."""
    cookie = args.cookie
    base = args.url if re.match(r"^https?://", args.url, re.I) else "http://" + args.url

    # ---- USERNAMES ----------------------------------------------------- #
    users = _scrape_usernames(base, args.domain, cookie=cookie)
    write_lines(users, args.users)
    sys.stderr.write(f"[harvest] usernames: {len(users)} -> {args.users}\n")
    if users:
        sys.stderr.write("           e.g. " + ", ".join(users[:8]) + "\n")

    # ---- PASSWORDS: personal data (from every reachable page) ---------- #
    pw_seen: set = set()
    passwords: list[str] = []

    def add_pw(w: str):
        if w and w not in pw_seen:
            pw_seen.add(w)
            passwords.append(w)

    # an OSINT list (from `wlkit osint`) goes FIRST - already target-ranked
    if getattr(args, "osint", None):
        if Path(args.osint).exists():
            for w in read_words(args.osint):
                add_pw(w)
            sys.stderr.write(f"[harvest] prepended OSINT list {args.osint} "
                             f"({len(passwords)} entries)\n")
        else:
            sys.stderr.write(f"[harvest] --osint file not found: {args.osint} (skipping)\n")

    # Personal data comes ONLY from authenticated/profile-type pages - never the
    # marketing homepage (whose words aren't personal and would flood the top).
    authed_pages = [base.rstrip("/") + p for p in
                    ("/profile", "/account", "/settings", "/me", "/dashboard")]
    all_dates: set = set()
    all_names: list[str] = []
    for url in authed_pages:
        st, _b, _u = _http(url, cookie=cookie)
        if st != 200:
            continue
        personal, dates, names = _scrape_personal(url, cookie)
        all_dates |= dates
        for n in names:
            if n not in all_names:
                all_names.append(n)
        for w in personal:          # personal candidates first (high priority)
            add_pw(w)
    if all_dates:
        sys.stderr.write(f"[harvest] dates/birthdate fragments: "
                         f"{', '.join(sorted(all_dates)[:10])}\n")
    if all_names:
        sys.stderr.write(f"[harvest] personal terms: {', '.join(all_names[:10])}\n")

    # ---- PASSWORDS: site keywords, mutated (appended after personal) --- #
    out_dir = Path(args.passwords).resolve().parent
    raw = str(out_dir / "_harvest_raw.txt")
    ns = _ns(input=base, strip_html=True, min_length=3, max_length=32,
             lowercase=True, sort=False, output=raw, cookie=cookie)
    cmd_extract(ns)
    if not args.no_mutate:
        mut = str(out_dir / "_harvest_mut.txt")
        ns = _ns(input=raw, case=True, leet=True, append=True, prepend=False,
                 years_back=6, min_length=1, max_length=32, output=mut)
        cmd_mutate(ns)
        kw_file = mut
    else:
        kw_file = raw
    for w in read_words(kw_file):
        add_pw(w)

    write_lines(passwords, args.passwords)
    sys.stderr.write(f"[harvest] passwords: {len(passwords)} -> {args.passwords} "
                     f"(personal-data candidates ranked first)\n")

    # cleanup temp
    for f in (raw, str(out_dir / "_harvest_mut.txt")):
        try:
            Path(f).unlink()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# auto  (the "thinking" mode - reasons about the target, then acts)
# --------------------------------------------------------------------------- #

def _t(tag: str, msg: str):
    """Print a reasoning-trace line, mirroring how an operator thinks aloud."""
    styles = _TAG_STYLE.get(tag, ("cyan",))
    print(f"  {c('[' + tag + ']', *styles)} {msg}")


# placeholders that are NOT a usable username hint (they describe the field)
GENERIC_PH = {"email", "username", "user", "login", "name", "email or username",
              "e.g.", "your email", "your username", "password", "••••••••",
              "enter your email", "enter username", ""}


def _looks_like_username(ph: str) -> str | None:
    """If a placeholder is a concrete example username (e.g. 'marco'), return it."""
    p = ph.strip().lower()
    if p in GENERIC_PH or "@" in p:
        return None
    # a single short alpha token that isn't a generic word -> likely a sample user
    if re.fullmatch(r"[a-z][a-z0-9._-]{1,20}", p) and " " not in p:
        return p
    return None


def _keywords_from_body(body: str) -> list[str]:
    """Mine likely keywords from HTML: badge/tag/chip text and #hashtags."""
    kws: list[str] = []
    seen = set()

    def add(w):
        w = w.strip().lower()
        if not (w and re.fullmatch(r"[a-z][a-z0-9]{2,}", w) and w not in seen):
            return
        if re.fullmatch(r"[0-9a-f]{3,8}", w):   # CSS hex colour (fff, f0f2f5) - skip
            return
        seen.add(w)
        kws.append(w)

    # tags / badges / chips / pills - class names that usually wrap keywords
    for m in re.finditer(r'class="[^"]*(?:badge|tag|chip|pill|label|keyword)[^"]*"[^>]*>'
                         r'\s*#?([^<]{2,30})<', body, re.I):
        add(m.group(1))
    # explicit #hashtags anywhere
    for m in re.finditer(r'#([A-Za-z][A-Za-z0-9]{2,20})', body):
        add(m.group(1))
    return kws


def _looks_like_login_page(body: str) -> bool:
    return bool(re.search(r'type=["\']password["\']', body, re.I)) or \
        bool(re.search(r'<title>[^<]*log\s*in', body, re.I))


# words that describe a password-mangling rule in prose
def _detect_password_rule(text: str):
    """Parse a described password rule (e.g. a bragging social post) into a list of
    wlkit templates. Returns (templates, human_description) or ([], '')."""
    t = re.sub(r"<[^>]+>", " ", text)
    t = html.unescape(t).lower()
    # only engage if it actually talks about passwords
    if "passsord" not in t and "password" not in t and "passwd" not in t:
        return [], ""

    prefix = "{cap}" if "capital" in t else ("{upper}" if "uppercase" in t else "{word}")
    if "leet" in t or "1337" in t:
        prefix = "{leet}"

    # ordered middle/end pieces
    mids = []
    if "year" in t:
        mids.append("{year}")
    if "number" in t or "digit" in t:
        mids.append("{num}")
    tail = ""
    if "exclamation" in t or "!" in t:
        tail = "!"
    elif "special char" in t or "symbol" in t:
        tail = "{sym}"

    templates = []
    if mids:
        for mid in mids:
            templates.append(prefix + mid + tail)
    elif tail:
        templates.append(prefix + tail)
    else:
        templates.append(prefix)
    desc = f"{prefix} + " + " / ".join(mids) + (f" + {tail}" if tail else "")
    return templates, desc


def cmd_auto(args):
    print(c("\n  ┏" + "━" * 62 + "┓", "purple"))
    print(c("  ┃", "purple") + c("  wlkit auto", "cyan", "bold")
          + c("  ·  reasoning about the target, then building the attack", "gray")
          + c("  ┃", "purple"))
    print(c("  ┗" + "━" * 62 + "┛", "purple"))

    cookie = getattr(args, "cookie", None)
    out_dir = _wl_dir()
    service = args.service or "web"
    web = service == "web"

    form = None
    fail = "F=Invalid"
    user, userlist = args.user, None
    n_users = 1

    # ---- target + (web) login recon ------------------------------------- #
    if web:
        tgt = args.target if re.match(r"^https?://", args.target, re.I) else "http://" + args.target
        parsed = urllib.parse.urlparse(tgt)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        _t("PHASE", f"web target = {tgt}  (host {host}, port {port})")
        _t("RECON", "probing common paths for a login form ...")
        form = _find_login_form(tgt)
        if not form:
            _t("RESULT", "no login form found. For SSH/FTP/etc pass --service ssh "
                         "--target host. Aborting.")
            return
        _t("OBSERVATION", f"login form at {form['path']} via {form['method'].upper()} "
                          f"- fields: {form['user_field']} / {form['pass_field']}")
        _t("PHASE", "learning what a FAILED login looks like ...")
        marker, _ = _detect_fail_marker(form["action_url"], form["user_field"],
                                        form["pass_field"], "wlkit_probe")
        if marker:
            fail = marker
            _t("OBSERVATION", f"failed logins say: {marker[2:]!r} -> using {marker}")
        else:
            _t("HYPOTHESIS", "no clear failure text; defaulting to F=Invalid.")
    else:
        # non-web: target is host[:port]
        tgt = None
        raw_t = re.sub(r"^\w+://", "", args.target)
        host = raw_t.split(":")[0]
        port = int(raw_t.split(":")[1]) if ":" in raw_t else \
            {"ssh": 22, "ftp": 21, "smb": 445, "mysql": 3306, "postgres": 5432}.get(service, 0)
        _t("PHASE", f"{service} target = {host}:{port}")
        if not (args.user or args.userlist):
            _t("RESULT", f"{service} needs --user or --userlist. Aborting.")
            return
        userlist = args.userlist

    # ---- WORDLIST SOURCE: rockyou by default, custom only if asked ------ #
    ROCKYOU = "/usr/share/wordlists/rockyou.txt"
    osint_file = getattr(args, "osint", None)
    if not getattr(args, "make_wordlist", False):
        pwlist = osint_file or getattr(args, "wordlist", None) or ROCKYOU
        if not Path(pwlist).exists():
            _t("RESULT", f"wordlist not found: {pwlist}. "
                         "Install rockyou or pass --osint / --wordlist / --make-wordlist. Aborting.")
            return
        n_pw = "?"
        src = "OSINT list" if osint_file else "default wordlist (no custom build requested)"
        _t("PHASE", f"password source: using {src}")
        _t("DECISION", f"using {pwlist}")
        # jump straight to username + attack assembly
        return _auto_finish(args, web, form, service, host, port, fail,
                            user, userlist, n_users, pwlist, n_pw, cookie, out_dir, tgt)

    # ---- INTEL: keywords + a described password rule -------------------- #
    intel_url = args.intel_url or (tgt if web else None)
    keywords, rule_templates, rule_desc = [], [], ""
    if intel_url:
        _t("PHASE", f"gathering intel from {intel_url}"
                    + (f" (Host: {args.intel_host})" if args.intel_host else ""))
        status, ibody, _u = _http(intel_url, cookie=cookie, host=args.intel_host)
        if status is None:
            _t("RESULT", f"could not reach {intel_url} (timeout / connection refused). "
                         "Is the box up and the VPN connected? Check --intel-host too. "
                         "Aborting.")
            return
        _t("OBSERVATION", f"fetched {len(ibody)} bytes (HTTP {status}).")
        if _looks_like_login_page(ibody) and "badge" not in ibody.lower():
            _t("HYPOTHESIS", "the intel page looks like a LOGIN page - the --cookie is "
                             "probably missing/expired, so I can't see the real content.")
        keywords = _keywords_from_body(ibody)
        if keywords:
            _t("OBSERVATION", f"keyword tags/badges: {', '.join(keywords[:12])}")
        else:
            _t("OBSERVATION", "no keyword tags/badges found on the intel page.")
        rule_templates, rule_desc = _detect_password_rule(ibody)
        if rule_templates:
            _t("OBSERVATION", f"target disclosed a password rule: {rule_desc}")
            _t("DECISION", f"encoding it as templates: {rule_templates}")

    # ---- PASSWORDS ------------------------------------------------------ #
    _t("PHASE", "building the password list ...")
    this_year = datetime.now().year
    years = [str(y) for y in range(this_year - 8, this_year + 1)]
    nums = [str(i) for i in range(0, 101)]
    syms = ["!", "@", "#", "$"]

    seen, pw = set(), []
    def add_pw(w):
        if w and 1 <= len(w) <= 40 and w not in seen:
            seen.add(w); pw.append(w)

    # (0) an OSINT list, if given, goes FIRST - it's already target-ranked
    if osint_file:
        if Path(osint_file).exists():
            n0 = 0
            for w in read_words(osint_file):
                before = len(pw); add_pw(w); n0 += len(pw) - before
            _t("DECISION", f"prepended {n0} OSINT candidates from {osint_file}")
        else:
            _t("HYPOTHESIS", f"--osint file not found: {osint_file} (skipping).")

    # (a) rule-based candidates FIRST - highest signal
    if rule_templates and keywords:
        rc = 0
        for kw in keywords:
            for tmpl in rule_templates:
                for cand in _apply_template(kw, tmpl, years, syms, nums):
                    add_pw(cand); rc += 1
        _t("DECISION", f"{len(pw)} rule-based candidates ranked first "
                       f"(e.g. {', '.join(pw[:4])})")

    # (b) personal data from an authed web page (CUPP-style)
    if web and cookie:
        for authed in ("/profile", "/account", "/me", "/dashboard"):
            st, _b, _u = _http(tgt.rstrip("/") + authed, cookie=cookie)
            if st == 200:
                personal, dates, names = _scrape_personal(tgt.rstrip("/") + authed, cookie)
                for w in personal:
                    add_pw(w)
                if personal:
                    _t("DECISION", f"+{len(personal)} personal-data candidates from {authed}")
                break

    # (c) site keywords, mutated (broad fallback)
    if intel_url and not args.no_site_words:
        raw = str(out_dir / "_auto_raw.txt")
        ns = _ns(input=intel_url, strip_html=True, min_length=3, max_length=32,
                 lowercase=True, sort=False, output=raw, cookie=cookie)
        try:
            cmd_extract(ns)
            mut = str(out_dir / "_auto_mut.txt")
            ns = _ns(input=raw, case=True, leet=True, append=True, prepend=False,
                     years_back=6, min_length=1, max_length=32, output=mut)
            cmd_mutate(ns)
            for w in read_words(mut):
                add_pw(w)
            for f in (raw, mut):
                try: Path(f).unlink()
                except OSError: pass
        except SystemExit:
            pass

    if not pw:
        hint = ""
        if args.no_site_words:
            hint = " (you passed --no-site-words, so there was no keyword fallback - " \
                   "drop it, or check the cookie/intel-host so intel scraping works)."
        _t("RESULT", "no password candidates could be built" + hint + " Aborting.")
        return
    pwlist = str(out_dir / "passwords.txt")
    write_lines(pw, pwlist)
    n_pw = len(pw)
    _t("DECISION", f"password list ready: {n_pw} candidates -> {pwlist}")

    return _auto_finish(args, web, form, service, host, port, fail,
                        user, userlist, n_users, pwlist, n_pw, cookie, out_dir, tgt)


def _auto_finish(args, web, form, service, host, port, fail,
                 user, userlist, n_users, pwlist, n_pw, cookie, out_dir, tgt):
    """Shared tail: pick username, assemble the hydra command, optionally run."""
    # ---- USERNAME (web auto-strategy if none given) --------------------- #
    if web and not user and not userlist:
        ph = form.get("user_placeholder", "")
        guess = _looks_like_username(ph)
        if guess:
            user = guess
            _t("DECISION", f"username from form placeholder: {user}")
        else:
            users = _scrape_usernames(tgt, cookie=cookie)
            userlist = str(out_dir / "usernames.txt")
            write_lines(users or ["admin", "administrator", "root", "user"], userlist)
            n_users = len(users) if users else 4
            _t("DECISION", f"username list: {n_users} -> {userlist}")

    # ---- assemble + run ------------------------------------------------- #
    _t("PHASE", "assembling the hydra command ...")
    if web:
        svc = "http-get-form" if form["method"] == "get" else "http-post-form"
        body = f"{form['user_field']}=^USER^&{form['pass_field']}=^PASS^"
        path = form["path"]
    else:
        svc, body, path = service, None, None
    threads = 4 if service in ("ssh", "ftp") else 16
    ns = _ns(tool="hydra", mode=svc, wordlist=pwlist, url=None, domain=None,
             target=host, port=port, threads=threads, extensions=None, status=None,
             match_codes=None, filter_size=None, user=user, userlist=userlist,
             path=path, body=body, fail=fail, run=False)
    cmd = _build_command(ns)
    printable = " ".join(shlex.quote(tok) for tok in cmd)
    print(c("\n  ┏━ PLAN COMPLETE " + "━" * 46 + "┓", "lime", "bold"))
    print("  " + c(printable, "cyan"))
    print(c("  ┗" + "━" * 62 + "┛", "lime", "bold"))
    _t("NOTE", f"search space ~= {n_pw} passwords x {n_users} username(s)")

    if args.run:
        _t("VALIDATE", "authorised targets only - running now.")
        try:
            subprocess.run(cmd + (["-f"] if "-f" not in cmd else []))
        except FileNotFoundError:
            _t("RESULT", f"'{cmd[0]}' not installed or not in PATH.")
    else:
        print("  (re-run with --run to execute, or copy the command above)")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def cmd_about(args):
    icon = {"GitHub": "", "X": "\U0001D54F", "LinkedIn": "in", "Email": "✉"}
    print(_banner())
    print()
    print("  " + c(f"wlkit {__version__}", "cyan", "bold") + c("  ·  Wordlist Kit", "gray"))
    print("  " + c("Author", "dim") + "  " + c(__author__, "bold"))
    for k, v in SOCIALS.items():
        print("  " + c(f"{k:<8}", "purple") + c(v, "blue"))
    print()
    print("  " + c("Found wlkit useful? A tip keeps it maintained ❤", "pink"))
    print("    " + c("\U0001F449 " + TIPS_URL, "lime", "bold"))
    print()


def _report(n: int, out: str | None):
    dest = out if out else "stdout"
    sys.stderr.write(f"[wlkit] {n} candidate(s) -> {dest}\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wlkit",
        description="Educational wordlist toolkit (crunch + CeWL + CUPP + rules). "
                    "Authorised testing only.",
        epilog=(f"author: {__author__}   |   "
                f"tips: {TIPS_URL}\n"
                + "   ".join(f"{k}: {v}" for k, v in SOCIALS.items())
                + "\n\nRun `wlkit` with no arguments for the interactive menu, "
                  "or `wlkit about` for author/support info."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"wlkit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=False)

    # about
    ab = sub.add_parser("about", help="show author, version, socials and tip link")
    ab.set_defaults(func=cmd_about)

    # gen
    g = sub.add_parser("gen", help="crunch-style pattern / charset generation")
    g.add_argument("--pattern", help="e.g. 'admin@%%^'  (@=a-z ,=A-Z %%=0-9 ^=symbols, \\ escapes)")
    g.add_argument("--min", type=int, help="min length (charset mode)")
    g.add_argument("--max", type=int, help="max length (charset mode)")
    g.add_argument("--charset", help="explicit charset for min/max mode")
    g.add_argument("-o", "--output")
    g.set_defaults(func=cmd_gen)

    # extract
    e = sub.add_parser("extract", help="CeWL-style unique word extraction")
    e.add_argument("input", help="local text/HTML file, or an http(s):// URL to fetch")
    e.add_argument("--cookie", help="Cookie header for authenticated pages, "
                                    "e.g. 'session=abc; jobs_authed=1'")
    e.add_argument("--strip-html", action="store_true", help="remove tags/scripts first")
    e.add_argument("--min-length", type=int, default=4)
    e.add_argument("--max-length", type=int, default=32)
    e.add_argument("--lowercase", action="store_true")
    e.add_argument("--sort", action="store_true")
    e.add_argument("-o", "--output")
    e.set_defaults(func=cmd_extract)

    # profile
    pr = sub.add_parser("profile", help="CUPP-style personalised wordlist")
    pr.add_argument("--words", nargs="+", help="names, birth years, keywords (space/comma separated)")
    pr.add_argument("--pet", nargs="+", help="pet / extra keywords")
    pr.add_argument("--combine", action="store_true", help="concatenate seed pairs")
    pr.add_argument("--leet", action="store_true", help="add leetspeak variants")
    pr.add_argument("--years-back", type=int, default=40)
    pr.add_argument("--min-length", type=int, default=6)
    pr.add_argument("--max-length", type=int, default=24)
    pr.add_argument("-o", "--output")
    pr.set_defaults(func=cmd_profile)

    # users
    u = sub.add_parser("users", help="username-format generation from full names")
    u.add_argument("input", help="file of 'First Last' per line")
    u.add_argument("--domain", help="append @domain to each username too")
    u.add_argument("-o", "--output")
    u.set_defaults(func=cmd_users)

    # mutate
    m = sub.add_parser("mutate", help="rule-based mutation of an existing list")
    m.add_argument("input")
    m.add_argument("--template", help="exact rule template, e.g. '{cap}{year}!' or "
                                      "'{W}{year}{sym}'. Tokens: {word}{cap}{upper}"
                                      "{lower}{leet}{year}{sym}{num}; literals kept.")
    m.add_argument("--symbols", help="comma list for {sym}, default '!,@,#,$'")
    m.add_argument("--nums", help="set for {num}: comma list or range like '0-100'")
    m.add_argument("--case", action="store_true", help="case variants")
    m.add_argument("--leet", action="store_true", help="leetspeak variants")
    m.add_argument("--append", action="store_true", help="append years/numbers/symbols")
    m.add_argument("--prepend", action="store_true", help="prepend numbers/symbols")
    m.add_argument("--years-back", type=int, default=15)
    m.add_argument("--min-length", type=int, default=1)
    m.add_argument("--max-length", type=int, default=32)
    m.add_argument("-o", "--output")
    m.set_defaults(func=cmd_mutate)

    # combine
    c = sub.add_parser("combine", help="merge / dedupe / sort wordlists")
    c.add_argument("inputs", nargs="+")
    c.add_argument("--sort", action="store_true", help="alphabetical")
    c.add_argument("--by-frequency", action="store_true", help="most common first")
    c.add_argument("-o", "--output")
    c.set_defaults(func=cmd_combine)

    # use
    us = sub.add_parser(
        "use",
        help="build a gobuster/ffuf/hydra command from a wordlist",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  wlkit use gobuster dir  words.txt --url http://10.10.1.1 -x php,txt\n"
            "  wlkit use gobuster dns  subs.txt  --domain tryfinanceme.local\n"
            "  wlkit use ffuf     ''   words.txt --url http://10.10.1.1/FUZZ -mc 200,301\n"
            "  wlkit use hydra ssh     pass.txt  --target 10.10.1.1 --user bob\n"
            "  wlkit use hydra http-post-form pass.txt --target 10.10.1.1 --userlist users.txt \\\n"
            "     --path /login --body 'user=^USER^&pass=^PASS^' --fail 'F=Invalid'\n"
        ),
    )
    us.add_argument("tool", choices=["gobuster", "ffuf", "hydra"])
    us.add_argument("mode", help="gobuster: dir|dns|vhost  hydra: ssh|ftp|smb|http-post-form|... "
                                 "ffuf: use '' (mode ignored)")
    us.add_argument("wordlist")
    # generic / http targets
    us.add_argument("--url", help="target URL (gobuster dir/vhost, ffuf; put FUZZ in ffuf URL)")
    us.add_argument("--domain", help="domain (gobuster dns)")
    us.add_argument("--target", help="host/IP (hydra)")
    us.add_argument("--port", type=int, help="service port (hydra)")
    us.add_argument("--threads", type=int, default=40)
    # gobuster/ffuf extras
    us.add_argument("-x", "--extensions", help="comma list, e.g. php,txt,html")
    us.add_argument("--status", help="gobuster: status codes to show")
    us.add_argument("--match-codes", help="ffuf -mc, e.g. 200,301")
    us.add_argument("--filter-size", help="ffuf -fs, e.g. 1234")
    # hydra login source + form
    us.add_argument("--user", help="single username (hydra -l)")
    us.add_argument("--userlist", help="username file (hydra -L)")
    us.add_argument("--path", help="request path for http-*-form, e.g. /login")
    us.add_argument("--body", help="form body, e.g. 'user=^USER^&pass=^PASS^'")
    us.add_argument("--fail", help="hydra failure condition, e.g. 'F=Invalid credentials'")
    us.add_argument("--run", action="store_true", help="execute after an explicit yes confirmation")
    us.set_defaults(func=cmd_use)

    # wizard
    wz = sub.add_parser("wizard", help="interactive: asks what you need, builds list + command")
    wz.set_defaults(func=cmd_wizard)

    # cupp (faithful CUPP port)
    cp = sub.add_parser(
        "cupp",
        help="CUPP mechanism (Mebus/cupp) - profile -> wordlist, interactive/flags/URL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  wlkit cupp -i\n"
               "  wlkit cupp --name marco --surname bianchi --nick marky "
               "--birthdate 14021995 --special --randnum --leet\n"
               "  wlkit cupp --from-url http://10.49.152.19:5002/profile "
               "--cookie 'jobs_authed=1' --leet -o marco.txt\n",
    )
    cp.add_argument("-i", "--interactive", action="store_true", help="ask CUPP questions")
    cp.add_argument("--from-url", help="auto-fill profile from an (authed) profile page")
    cp.add_argument("--cookie", help="cookie for --from-url")
    cp.add_argument("--name"); cp.add_argument("--surname"); cp.add_argument("--nick")
    cp.add_argument("--birthdate", help="DDMMYYYY")
    cp.add_argument("--wife"); cp.add_argument("--wifen"); cp.add_argument("--wifeb")
    cp.add_argument("--kid"); cp.add_argument("--kidn"); cp.add_argument("--kidb")
    cp.add_argument("--pet"); cp.add_argument("--company")
    cp.add_argument("--words", nargs="+", help="extra keywords")
    cp.add_argument("--special", action="store_true", help="append special-char combos")
    cp.add_argument("--randnum", action="store_true", help="append random numbers (numfrom..numto)")
    cp.add_argument("--leet", action="store_true", help="also add leetspeak of every word")
    cp.add_argument("--years", help="comma list, overrides default 1990..2030")
    cp.add_argument("--numfrom", type=int, default=0)
    cp.add_argument("--numto", type=int, default=100)
    cp.add_argument("--wcfrom", type=int, default=5, help="keep words longer than this")
    cp.add_argument("--wcto", type=int, default=12, help="keep words shorter than this")
    cp.add_argument("-o", "--output")
    cp.set_defaults(func=cmd_cupp)

    # osint (people/keywords -> strong wordlist)
    oi = sub.add_parser(
        "osint",
        help="build a target-specific wordlist from OSINT (imported file, inline "
             "names, or a PUBLIC page). Does not scrape ToS-protected platforms.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  wlkit osint --names 'John Smith, Jane Doe' --company acme --leet -o acme.txt\n"
               "  wlkit osint --import employees.csv --company acme --big -o acme.txt\n"
               "  wlkit osint --from-url https://acme.com/team --company acme -o acme.txt\n",
    )
    oi.add_argument("--names", nargs="+", help="inline 'First Last' names (comma/space sep)")
    oi.add_argument("--import", dest="import_file", help="OSINT file to ingest "
                    "(txt/csv, a profile export, or theHarvester JSON output)")
    oi.add_argument("--from-url", help="a PUBLIC page to mine (team/about page)")
    oi.add_argument("--cookie", help="cookie for --from-url if needed")
    oi.add_argument("--host", help="Host header for --from-url (vhost by IP)")
    oi.add_argument("--company", help="company/employer keyword")
    oi.add_argument("--keywords", nargs="+", help="extra seed keywords")
    oi.add_argument("--leet", action="store_true", help="add leetspeak variants")
    oi.add_argument("--deep", action="store_true", help="per-person: add special chars + random numbers (bigger)")
    oi.add_argument("--big", action="store_true", help="expand {num} to 0-100 (bigger)")
    oi.add_argument("--users", help="also write a usernames file (from emails/names, "
                                    "e.g. a theHarvester JSON import)")
    oi.add_argument("-o", "--output", default="osint_wordlist.txt")
    oi.set_defaults(func=cmd_osint)

    # harvest (URL -> users + passwords)
    hv = sub.add_parser(
        "harvest",
        help="scrape a URL (with --cookie for authed pages) into users.txt + passwords.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "  wlkit harvest http://10.49.152.19:5002 \\\n"
               "     --cookie 'session=...; jobs_authed=1' \\\n"
               "     --users users.txt --passwords passwords.txt\n",
    )
    hv.add_argument("url", help="site/base URL to scrape")
    hv.add_argument("--cookie", help="Cookie header for authenticated pages")
    hv.add_argument("--domain", help="email domain to append to usernames")
    hv.add_argument("--users", default="users.txt", help="username output file")
    hv.add_argument("--passwords", default="passwords.txt", help="password output file")
    hv.add_argument("--osint", help="an OSINT wordlist (from `wlkit osint`) to prepend "
                                    "high-priority to the passwords output")
    hv.add_argument("--no-mutate", action="store_true",
                    help="don't apply mutation rules to the keyword passwords")
    hv.set_defaults(func=cmd_harvest)

    # auto ("thinking" mode)
    au = sub.add_parser(
        "auto",
        help="give it a URL; it reasons about the login, builds both lists, "
             "and assembles the hydra command",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  wlkit auto http://10.49.152.19:5003 --run\n"
               "  wlkit auto http://site/login --user marco\n",
    )
    au.add_argument("target", help="web login URL, or host[:port] for --service ssh/ftp/...")
    au.add_argument("--service", choices=["web", "ssh", "ftp", "smb", "mysql", "postgres"],
                    default="web", help="what to attack (default web login form)")
    au.add_argument("--cookie", help="session Cookie header for authenticated pages")
    au.add_argument("--intel-url", help="page to mine keywords + a disclosed password "
                                        "rule from (e.g. a social feed); defaults to the "
                                        "web target")
    au.add_argument("--intel-host", help="Host header for --intel-url (reach a vhost by IP)")
    au.add_argument("--user", help="username (required for non-web services)")
    au.add_argument("--userlist", help="username list file (non-web)")
    au.add_argument("--no-site-words", action="store_true",
                    help="skip the broad CeWL keyword fallback (rule/personal only)")
    au.add_argument("--make-wordlist", action="store_true",
                    help="build a targeted wordlist from intel/rule/personal data "
                         "(default: use rockyou.txt)")
    au.add_argument("--wordlist", help="use this wordlist file (default rockyou.txt) "
                                       "when not building a custom one")
    au.add_argument("--osint", help="an OSINT wordlist (from `wlkit osint`): used as the "
                                    "password list, or prepended high-priority when "
                                    "--make-wordlist is set")
    au.add_argument("--run", action="store_true", help="execute the assembled command")
    au.set_defaults(func=cmd_auto)

    return p


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
        if not getattr(args, "func", None):
            # no subcommand -> drop into the interactive menu (asks, no flags needed)
            cmd_wizard(args)
            return
        args.func(args)
    except (KeyboardInterrupt, EOFError):
        sys.stderr.write("\n[wlkit] good bye \U0001F44B\n")
        sys.exit(130)


if __name__ == "__main__":
    main()
