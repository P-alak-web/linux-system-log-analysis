import argparse
from collections import Counter
from datetime import datetime
import ipaddress
import os
import re
import sys
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Linux System Log Analyzer"
    )

    parser.add_argument(
        "-l", "--log",
        default="logs/OpenSSH_2k.log"
    )

    parser.add_argument(
        "-o", "--output",
        default="reports/advanced_analysis_report.md"
    )

    return parser.parse_args()
def analyze_logs(log_file_path):
    if not os.path.isfile(log_file_path):
        print(f"[!] Log file not found: {log_file_path}")
        sys.exit(1)

    failed_count = 0
    success_count = 0
    failed_ips = Counter()
    targeted_users = Counter()
    event_timeline = []

    failed_pattern = re.compile(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
        r".*?Failed password for (?:invalid user )?([^\s]+)"
        r" from ([^\s]+)"
    )

    success_pattern = re.compile(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
        r".*?Accepted (?:password|publickey) for ([^\s]+)"
        r" from ([^\s]+)"
    )

    with open(
        log_file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        for line in file:
            fail_match = failed_pattern.search(line)

            if fail_match:
                timestamp, user, ip = fail_match.groups()

                try:
                    ip = str(ipaddress.ip_address(ip))
                except ValueError:
                    continue

                failed_count += 1
                failed_ips[ip] += 1
                targeted_users[user] += 1

                event_timeline.append({
                    "type": "FAILED",
                    "time": timestamp,
                    "user": user,
                    "ip": ip
                })

                continue

            success_match = success_pattern.search(line)

            if success_match:
                timestamp, user, ip = success_match.groups()

                try:
                    ip = str(ipaddress.ip_address(ip))
                except ValueError:
                    continue

                success_count += 1

                event_timeline.append({
                    "type": "SUCCESS",
                    "time": timestamp,
                    "user": user,
                    "ip": ip
                })

    return (
        failed_count,
        success_count,
        failed_ips,
        targeted_users,
        event_timeline
    )


def generate_report(
    output_path,
    failed_count,
    success_count,
    failed_ips,
    targeted_users,
    event_timeline
):
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    report = [
        "# LINUX SYSTEM LOG ANALYSIS REPORT",
        "",
        "CyberSNova Security Internship - Blue Team Track",
        "",
        f"Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        f"- Total Failed Login Records: {failed_count}",
        f"- Total Successful Login Records: {success_count}",
        f"- Unique Source IPs with Failed Logins: {len(failed_ips)}",
        "",
        "---",
        "",
        "## 2. Top 10 Suspicious Source IP Addresses",
        "",
        "| Rank | IP Address | Failed Records | Risk Level |",
        "|---|---|---:|---|"
    ]

    for rank, (ip, count) in enumerate(failed_ips.most_common(10), 1):
        risk = "HIGH" if count > 10 else "MEDIUM" if count > 5 else "LOW"
        report.append(
            f"| {rank} | `{ip}` | {count} | {risk} |"
        )

    report.extend([
        "",
        "---",
        "",
        "## 3. Most Targeted Usernames",
        "",
        "| Username | Target Frequency |",
        "|---|---:|"
    ])

    for user, count in targeted_users.most_common(5):
        report.append(f"| `{user}` | {count} |")

    report.extend([
        "",
        "---",
        "",
        "## 4. Login Events Timeline",
        "",
        "| Timestamp | Event Type | Username | Source IP |",
        "|---|---|---|---|"
    ])

    for event in event_timeline[:10]:
        report.append(
            f"| {event['time']} | {event['type']} | "
            f"`{event['user']}` | `{event['ip']}` |"
        )

    report.extend([
        "",
        "---",
        "",
        "## 5. Security Recommendations",
        "",
        "1. Investigate IPs with unusually high failed-login counts.",
        "2. Prefer SSH key-based authentication.",
        "3. Disable direct root SSH login where appropriate.",
        "4. Monitor authentication logs regularly.",
        "5. Consider rate limiting repeated login attempts.",
        "",
        "**Note:** Risk levels are heuristic indicators, not proof "
        "of malicious activity. Log records may not represent "
        "distinct login attempts."
    ])

    with open(output_path, "w", encoding="utf-8") as file:
        file.write("\n".join(report))

    print(f"[+] Report generated: {output_path}")


def main():
    args = parse_arguments()

    (
        failed_count,
        success_count,
        failed_ips,
        targeted_users,
        event_timeline
    ) = analyze_logs(args.log)

    print("\n" + "=" * 45)
    print("       LINUX SYSTEM LOG ANALYSIS")
    print("=" * 45)

    print(f"[+] Failed Login Records : {failed_count}")
    print(f"[+] Successful Logins    : {success_count}")
    print(f"[+] Unique Source IPs    : {len(failed_ips)}")

    print("\n[Top 5 Source IPs with Failed Logins]")

    for ip, count in failed_ips.most_common(5):
        print(f"{ip} : {count} failed records")

    generate_report(
        args.output,
        failed_count,
        success_count,
        failed_ips,
        targeted_users,
        event_timeline
    )


if __name__ == "__main__":
    main()
