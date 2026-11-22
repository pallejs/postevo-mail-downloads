"""Transfer approved binary archives; never access the private source repository."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import urllib.parse
import urllib.request
import zipfile

MAX_ARCHIVE = 350 * 1024 * 1024
MAX_INSTALLER = 150 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Archive redirects are not accepted")


def expected_files(path):
    expected = {}
    for line in path.read_text().splitlines():
        digest, name = line.split("  ", 1)
        if (len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
                or Path(name).name != name or not name.startswith("postevo-mail-0.41.0-")):
            raise ValueError("Invalid approved file manifest")
        if name in expected:
            raise ValueError("Duplicate approved file name")
        expected[name] = digest
    if len(expected) != 13:
        raise ValueError("Expected exactly thirteen approved application packages")
    return expected


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    urls = json.loads(event["inputs"]["artifact_urls"])
    if not isinstance(urls, list) or len(urls) != 5:
        raise ValueError("Exactly five approved binary archives are required")
    for url in urls:
        if not isinstance(url, str) or len(url) > 8192 or any(c in url for c in "\r\n"):
            raise ValueError("Invalid archive URL")
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or not (parsed.hostname or "").endswith(".oaiusercontent.com")
                or parsed.username or parsed.password or parsed.port not in (None, 443)):
            raise ValueError("Archive URL must be on the approved HTTPS file host")
        print("::add-mask::" + url, flush=True)
    expected = expected_files(Path("SHA256SUMS.txt"))
    out = Path("release-files")
    # A retry must verify every file again, without retaining files from an earlier attempt.
    if out.exists():
        raise ValueError("The output directory must be new")
    out.mkdir()
    opener = urllib.request.build_opener(NoRedirect())
    found = set()
    for index, url in enumerate(urls, 1):
        print("Downloading approved binary archive " + str(index) + "/5", flush=True)
        with tempfile.TemporaryFile() as archive_file:
            total = 0
            with opener.open(url, timeout=60) as response:
                if response.status != 200:
                    raise ValueError("Archive request failed")
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ARCHIVE:
                        raise ValueError("Archive is too large")
                    archive_file.write(chunk)
            archive_file.seek(0)
            with zipfile.ZipFile(archive_file) as archive:
                if len(archive.infolist()) > 100:
                    raise ValueError("Too many archive entries")
                for entry in archive.infolist():
                    name = Path(entry.filename).name
                    if name not in expected or entry.is_dir():
                        continue
                    if name in found or entry.file_size > MAX_INSTALLER:
                        raise ValueError("Duplicate or oversized installer")
                    digest = hashlib.sha256()
                    size = 0
                    with archive.open(entry) as src, (out / name).open("wb") as dst:
                        while True:
                            chunk = src.read(1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            if size > MAX_INSTALLER:
                                raise ValueError("Installer exceeded size limit")
                            digest.update(chunk)
                            dst.write(chunk)
                    if digest.hexdigest() != expected[name]:
                        raise ValueError("Installer checksum mismatch: " + name)
                    found.add(name)
                    print("Verified " + name, flush=True)
    if found != set(expected):
        raise ValueError("Some approved installers are missing")
    for name in ("SHA256SUMS.txt", "LICENSE-MIT", "LICENSE-APACHE", "NOTICE.txt"):
        shutil.copyfile(name, out / name)
    print("All thirteen installers verified; seventeen release files are ready.", flush=True)


if __name__ == "__main__":
    main()
