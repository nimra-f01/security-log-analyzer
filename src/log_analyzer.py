
import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<status>SUCCESS|FAILED) "
    r"user=(?P<username>[A-Za-z0-9_.@-]+) "
    r"ip=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})$"
)


def parse_log_line(line):
    """Parse one log line. Return a record or None if invalid."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    record = match.groupdict()

    try:
        datetime.strptime(record["timestamp"], "%Y-%m-%d %H:%M:%S")
        octets = [int(part) for part in record["ip"].split(".")]
        if any(octet < 0 or octet > 255 for octet in octets):
            return None
    except ValueError:
        return None

    return record


def analyze_log(path, threshold=5):
    """Analyze authentication logs and return summary statistics."""
    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    totals = Counter()
    failures_by_ip = Counter()
    users_by_ip = defaultdict(set)
    failures_by_user = Counter()
    invalid_lines = 0

    with Path(path).open("r", encoding="utf-8") as log_file:
        for line in log_file:
            if not line.strip():
                continue

            record = parse_log_line(line)
            if record is None:
                invalid_lines += 1
                continue

            status = record["status"]
            ip = record["ip"]
            username = record["username"]

            totals[status] += 1
            users_by_ip[ip].add(username)

            if status == "FAILED":
                failures_by_ip[ip] += 1
                failures_by_user[username] += 1

    suspicious_ips = {
        ip: count
        for ip, count in failures_by_ip.items()
        if count >= threshold
    }

    return {
        "successful": totals["SUCCESS"],
        "failed": totals["FAILED"],
        "total": totals["SUCCESS"] + totals["FAILED"],
        "invalid_lines": invalid_lines,
        "failures_by_ip": failures_by_ip,
        "failures_by_user": failures_by_user,
        "users_by_ip": users_by_ip,
        "suspicious_ips": suspicious_ips,
        "threshold": threshold,
    }


def print_report(results):
    print("\nSECURITY LOG ANALYZER")
    print("=" * 40)
    print(f"Total valid attempts: {results['total']}")
    print(f"Successful logins:    {results['successful']}")
    print(f"Failed logins:        {results['failed']}")
    print(f"Invalid log lines:    {results['invalid_lines']}")
    print(f"Detection threshold:  {results['threshold']} failed attempts")
    print("\nFailed attempts by IP:")

    if results["failures_by_ip"]:
        for ip, count in results["failures_by_ip"].most_common():
            print(f"  {ip}: {count}")
    else:
        print("  None")

    print("\nPotential brute-force activity:")
    if results["suspicious_ips"]:
        for ip, count in sorted(
            results["suspicious_ips"].items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            print(f"  [HIGH] {ip}: {count} failed attempts")
    else:
        print("  No IPs met the configured threshold.")

    print("\nFailed attempts by username:")
    if results["failures_by_user"]:
        for username, count in results["failures_by_user"].most_common():
            print(f"  {username}: {count}")
    else:
        print("  None")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze synthetic authentication logs."
    )
    parser.add_argument(
        "--log",
        default="sample_logs/auth.log",
        help="Path to the authentication log file",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts from one IP needed to trigger an alert",
    )
    args = parser.parse_args()

    try:
        results = analyze_log(args.log, args.threshold)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print_report(results)


if __name__ == "__main__":
    main()

