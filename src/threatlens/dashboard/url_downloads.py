"""ThreatLens dashboard - fetch a report PDF from a URL, then queue it for ingest.

Backs the Ingest page's "Download from URL" box. Each download runs in its
own thread, saving into the report folder (docs/database/CTI) under a
temporary dot-name and renaming it once complete, so neither the pipeline
nor the Report Files page ever sees a half-downloaded file. Once the file
is in place it is handed to the ingest queue with the engine and verbosity
chosen when the download was started.

A response is accepted as a PDF only if its body starts with the "%PDF-"
magic bytes - a Content-Type header alone is not trusted, as servers often
send PDFs as application/octet-stream, or send an HTML landing page for a
"PDF" link.

Like the ingest queue, the download list lives in memory and is lost when
the dashboard restarts.

The dashboard has no authentication and may be reachable from the LAN, so
the fetcher is locked down against being used to reach internal services
(SSRF): only http(s) on ports 80/443, no credentials in the URL, no proxies,
and every connection - including each redirect hop - is made to an address
the server resolved and checked itself to be publicly routable. Checking at
connect time, not just when the URL is submitted, is what stops a redirect
or a DNS answer that changes between lookups from reaching a private host.
"""

from __future__ import annotations

import http.client
import ipaddress
import itertools
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path
from typing import Any

from threatlens.dashboard.ingest_jobs import queue
from threatlens.dashboard.routes.report_files import CTI_DIR

MAX_BYTES = 200 * 1024 * 1024
CHUNK = 64 * 1024
TIMEOUT = 30  # seconds per connect/read, not for the whole download
USER_AGENT = "Mozilla/5.0 (compatible; ThreatLens report fetcher)"
PDF_MAGIC = b"%PDF-"
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
MAX_ACTIVE = 3
MAX_REDIRECTS = 5


class DownloadError(Exception):
    pass


@dataclass
class Download:
    id: int
    url: str
    db_path: Path
    engine: str
    verbose: int
    filename: str | None = None
    status: str = "connecting"  # connecting, downloading, queued, failed, cancelled
    bytes_done: int = 0
    bytes_total: int | None = None
    content_type: str | None = None
    message: str = "Connecting"
    job_id: int | None = None
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    cancel_requested: bool = False

    @property
    def active(self) -> bool:
        return self.status in ("connecting", "downloading")

    def summary(self) -> dict[str, Any]:
        percent = None
        if self.status == "queued":
            percent = 100.0
        elif self.bytes_total:
            percent = round(min(self.bytes_done / self.bytes_total, 1.0) * 100, 1)
        return {
            "id": self.id,
            "url": self.url,
            "filename": self.filename,
            "status": self.status,
            "bytes_done": self.bytes_done,
            "bytes_total": self.bytes_total,
            "percent": percent,
            "content_type": self.content_type,
            "message": self.message,
            "job_id": self.job_id,
            "engine": self.engine,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


def validate_url(url: str) -> str:
    """The URL stripped, if it is an allowed http(s) URL to a public host."""
    url = url.strip()
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise DownloadError(f"Invalid URL: {exc}") from exc
    if parts.scheme.lower() not in ALLOWED_SCHEMES or not parts.hostname:
        raise DownloadError("Enter a full http:// or https:// URL")
    if parts.username is not None or parts.password is not None:
        raise DownloadError("URLs with a username or password are not allowed")
    if port is not None and port not in ALLOWED_PORTS:
        raise DownloadError(f"Only the standard web ports ({', '.join(map(str, sorted(ALLOWED_PORTS)))}) are allowed")
    # Fail fast on an obviously internal host; the connect-time check below
    # is the one that actually enforces it.
    public_addresses(parts.hostname, port or (443 if parts.scheme.lower() == "https" else 80))
    return url


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def public_addresses(host: str, port: int) -> list[tuple[Any, ...]]:
    """getaddrinfo() results for host:port, refusing it if any address is not public."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DownloadError(f"Could not resolve {host}") from exc
    for *_, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        if not _is_public(ip):
            where = f"{host} resolves to {ip}, which is" if host.strip("[]") != sockaddr[0] else f"{ip} is"
            raise DownloadError(f"{where} a private or reserved address; only public hosts are allowed")
    return infos


def _guarded_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    """socket.create_connection, but only to addresses public_addresses() vetted."""
    host, port = address
    if port not in ALLOWED_PORTS:
        raise DownloadError(f"Port {port} is not allowed")
    last_error: OSError | None = None
    for family, socktype, proto, _, sockaddr in public_addresses(host, port):
        sock = socket.socket(family, socktype, proto)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)  # the vetted IP, never a fresh lookup
            return sock
        except OSError as exc:
            sock.close()
            last_error = exc
    raise last_error or OSError(f"Could not connect to {host}")


class _GuardedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _guarded_create_connection


class _GuardedHTTPSConnection(http.client.HTTPSConnection):
    # TLS is still verified against the URL's hostname - only the socket
    # underneath is swapped for one to a vetted address.
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._create_connection = _guarded_create_connection


class _GuardedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(_GuardedHTTPConnection, req)


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req: urllib.request.Request) -> Any:
        return self.do_open(_GuardedHTTPSConnection, req, context=self._context)


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(urllib.parse.urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# No ProxyHandler (an env proxy would make the server, not us, pick the
# address), and no ftp/file/data handlers - so nothing but guarded http(s).
_opener = urllib.request.OpenerDirector()
for _handler in (
    _GuardedHTTPHandler(),
    _GuardedHTTPSHandler(),
    _GuardedRedirectHandler(),
    urllib.request.HTTPErrorProcessor(),
    urllib.request.HTTPDefaultErrorHandler(),
):
    _opener.add_handler(_handler)


def _filename_from(response_url: str, headers: Message) -> str:
    """A safe .pdf filename from the Content-Disposition header, else the URL path."""
    name = headers.get_filename() or ""
    if not name:
        name = urllib.parse.unquote(Path(urllib.parse.urlsplit(response_url).path).name)
    name = Path(name.replace("\\", "/")).name
    stem = Path(name).stem if name.lower().endswith(".pdf") else name
    stem = re.sub(r"[^A-Za-z0-9._ -]+", "_", stem).strip(" ._")[:150]
    return f"{stem or 'download-' + time.strftime('%Y%m%d-%H%M%S')}.pdf"


def _unique_target(filename: str) -> Path:
    """CTI_DIR/filename, numbered "name (2).pdf" etc. if that name is taken."""
    target = CTI_DIR / filename
    stem = target.stem
    for n in itertools.count(2):
        if not target.exists():
            return target
        target = CTI_DIR / f"{stem} ({n}).pdf"
    raise AssertionError("unreachable")


class DownloadManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._downloads: dict[int, Download] = {}
        self._ids = itertools.count(1)

    def start(self, url: str, db_path: Path, engine: str, verbose: int) -> Download:
        url = validate_url(url)
        with self._lock:
            if sum(d.active for d in self._downloads.values()) >= MAX_ACTIVE:
                raise DownloadError(f"Already {MAX_ACTIVE} downloads running - wait for one to finish")
            download = Download(next(self._ids), url, db_path, engine, verbose)
            self._downloads[download.id] = download
        threading.Thread(target=self._run, args=(download,), daemon=True, name=f"download-{download.id}").start()
        return download

    def downloads(self) -> list[Download]:
        with self._lock:
            return list(self._downloads.values())

    def cancel(self, download_id: int) -> Download | None:
        with self._lock:
            download = self._downloads.get(download_id)
        if download is not None and download.active:
            download.cancel_requested = True
        return download

    def clear_finished(self) -> int:
        with self._lock:
            done = [i for i, d in self._downloads.items() if not d.active]
            for i in done:
                del self._downloads[i]
        return len(done)

    def _run(self, download: Download) -> None:
        partial: Path | None = None
        try:
            request = urllib.request.Request(download.url, headers={"User-Agent": USER_AGENT, "Accept": "application/pdf,*/*"})
            with _opener.open(request, timeout=TIMEOUT) as response:
                download.content_type = response.headers.get_content_type()
                length = response.headers.get("Content-Length")
                download.bytes_total = int(length) if length and length.isdigit() else None
                if download.bytes_total and download.bytes_total > MAX_BYTES:
                    raise DownloadError(f"File is {download.bytes_total / 1e6:.0f} MB, over the {MAX_BYTES // 2**20} MB limit")

                first = response.read(len(PDF_MAGIC))
                if first != PDF_MAGIC:
                    raise DownloadError(f"Not a PDF file (server sent {download.content_type})")

                CTI_DIR.mkdir(parents=True, exist_ok=True)
                download.filename = _filename_from(response.geturl(), response.headers)
                partial = CTI_DIR / f".{download.filename}.{download.id}.part"
                download.status = "downloading"
                download.message = "Downloading"

                with partial.open("wb") as out:
                    out.write(first)
                    download.bytes_done = len(first)
                    while chunk := response.read(CHUNK):
                        if download.cancel_requested:
                            download.status = "cancelled"
                            download.message = "Cancelled"
                            return
                        out.write(chunk)
                        download.bytes_done += len(chunk)
                        if download.bytes_done > MAX_BYTES:
                            raise DownloadError(f"File is over the {MAX_BYTES // 2**20} MB limit")

            if download.bytes_total and download.bytes_done < download.bytes_total:
                raise DownloadError("Connection closed before the download finished")

            with self._lock:  # two downloads of the same name must not pick the same target
                target = _unique_target(download.filename)
                partial.replace(target)
            partial = None
            download.filename = target.name

            jobs = queue.enqueue([target], download.db_path, download.engine, download.verbose)
            download.job_id = jobs[0].id if jobs else None
            download.status = "queued"
            download.message = f"Saved as {target.name}, queued for ingest"
        except DownloadError as exc:
            download.status, download.message = "failed", str(exc)
        except urllib.error.HTTPError as exc:
            download.status, download.message = "failed", f"Server returned HTTP {exc.code} {exc.reason}"
        except urllib.error.URLError as exc:
            download.status, download.message = "failed", f"Could not connect: {exc.reason}"
        except (OSError, ValueError) as exc:
            download.status, download.message = "failed", f"Download failed: {exc}"
        finally:
            if partial is not None:
                partial.unlink(missing_ok=True)
            download.finished_at = time.time()


downloads = DownloadManager()
