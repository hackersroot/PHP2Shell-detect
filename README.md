# PHP2Shell Detect

A PHP version checker for an authorised local lab. It compares a PHP version disclosed by the web server with the upstream fixed releases for CVE-2026-109618 and CVE-2026-109619.

## Run the passive check

From this repository directory:

```bash
python3 detect.py http://127.0.0.1:18110/index.php
