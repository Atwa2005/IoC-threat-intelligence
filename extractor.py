import re

def extract_iocs(file_name):

    with open(file_name, "r") as file:
        log = file.read()

    alert_pattern = r"Alert ID:\s*(.+)"

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    url_pattern = r"https?://[^\s]+"
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    alert = re.search(alert_pattern, log)

    return {
        "alert_id": alert.group(1) if alert else "Unknown",

        "ips": re.findall(ip_pattern, log),

        "urls": re.findall(url_pattern, log),

        "domains": re.findall(domain_pattern, log),

        "md5": re.findall(md5_pattern, log),

        "sha1": re.findall(sha1_pattern, log),

        "sha256": re.findall(sha256_pattern, log)
    }