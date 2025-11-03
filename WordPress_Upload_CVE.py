import requests
import re
from urllib.parse import urljoin, urlparse

# === Configuration ===
TARGETS_FILE = "targets.txt"
OUTPUT_FILE = "results.txt"
REQUEST_TIMEOUT = 10.0
USER_AGENT = "Mozilla/5.0 (compatible; Scanner/1.0)"

# Plugin paths to check for version info
PLUGIN_PATHS = [
    "wp-content/plugins/wp-file-upload/readme.txt",
    "wp-content/plugins/wp-file-upload/wp-file-upload.php",
    "wp-content/plugins/wp-file-upload/js/jquery-file-upload/js/jquery.fileupload.js",
]

# Target version info (string + regex for safety)
VERSION_STRING = "2.7.6"
VERSION_REGEX = re.compile(r"\b2\.7\.6\b")

# === Functions ===


def load_targets(filename):
    """Load non-empty lines from a file as targets."""
    with open(filename, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def ensure_scheme(url: str) -> str:
    """
    Ensure the URL has a scheme. Prefer https if no scheme provided.
    Returns a URL like 'https://example.com'.
    """
    parsed = urlparse(url, scheme="")
    if parsed.scheme:
        # user provided a scheme; reconstruct base
        return f"{parsed.scheme}://{parsed.netloc or parsed.path}"
    else:
        # no scheme — assume https
        return "https://" + url.lstrip("/")


def check_target(base_url: str, session: requests.Session):
    """
    Check all PLUGIN_PATHS for the given base_url.
    Returns a list of result strings (possibly empty). Does not stop on first match.
    """
    results = []
    normalized_base = ensure_scheme(base_url)
    print(f"\n[*] Checking {normalized_base}")

    for path in PLUGIN_PATHS:
        full_url = urljoin(normalized_base.rstrip("/") + "/", path)
        try:
            resp = session.get(full_url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            print(f"[!] Error fetching {full_url}: {e}")
            results.append(f"{base_url} - {full_url} - ERROR: {e}")
            continue

        status = resp.status_code
        if status == 200:
            content = resp.text or ""
            # check for exact version token
            if VERSION_REGEX.search(content):
                print(f"[+] Vulnerable version {VERSION_STRING} found at: {full_url}")
                results.append(f"{base_url} - {full_url} - VULNERABLE {VERSION_STRING}")
            else:
                # plugin exists but exact version not found
                # still report plugin presence and show short snippet for manual review
                snippet = content[:200].replace("\n", " ").replace("\r", " ")
                print(f"[~] Plugin present at {full_url} (version not clearly {VERSION_STRING})")
                results.append(f"{base_url} - {full_url} - Plugin present (no {VERSION_STRING}) - snippet: {snippet}")
        elif status == 403:
            print(f"[!] Forbidden (403) at {full_url}")
            results.append(f"{base_url} - {full_url} - 403 Forbidden")
        elif status == 404:
            print(f"[ ] Not found (404): {full_url}")
            # don't clutter results with every 404 — include only if no results found later
        else:
            print(f"[?] Got status {status} at {full_url}")
            results.append(f"{base_url} - {full_url} - status {status}")

    return results


def write_results(urls, filename):
    """Write the list of result strings to a file (one per line)."""
    with open(filename, "w", encoding="utf-8") as fh:
        for line in urls:
            fh.write(line + "\n")
    print(f"\n[+] Written {len(urls)} result lines to {filename}")


# === Main Execution ===


def main():
    targets = load_targets(TARGETS_FILE)
    if not targets:
        print("No targets loaded. Put one target per line in", TARGETS_FILE)
        return

    found_results = []

    # use a session for connection reuse and set a UA
    with requests.Session() as session:
        session.headers.update({"User-Agent": USER_AGENT})

        for idx, target in enumerate(targets, start=1):
            print(f"\n=== [{idx}/{len(targets)}] {target} ===")
            target_results = check_target(target, session)
            if target_results:
                # extend with any findings for this target
                found_results.extend(target_results)
            else:
                # no specific findings — note that nothing obvious was found
                found_results.append(f"{target} - No findings for checked plugin paths")

    # persist results
    write_results(found_results, OUTPUT_FILE)


if __name__ == "__main__":
    main()
