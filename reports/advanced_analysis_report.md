# LINUX SYSTEM LOG ANALYSIS REPORT

CyberSNova Security Internship - Blue Team Track

Generated on:** 2026-11-07 20:10:01

---

## 1. Executive Summary

- Total Failed Login Records: 519
- Total Successful Login Records: 1
- Unique Source IPs with Failed Logins: 23

---

## 2. Top 10 Suspicious Source IP Addresses

| Rank | IP Address | Failed Records | Risk Level |
|---|---|---:|---|
| 1 | `183.62.140.253` | 286 | HIGH |
| 2 | `187.141.143.180` | 80 | HIGH |
| 3 | `103.99.0.122` | 46 | HIGH |
| 4 | `112.95.230.3` | 26 | HIGH |
| 5 | `5.188.10.180` | 17 | HIGH |
| 6 | `185.190.58.151` | 17 | HIGH |
| 7 | `123.235.32.19` | 7 | MEDIUM |
| 8 | `119.4.203.64` | 6 | MEDIUM |
| 9 | `52.80.34.196` | 5 | LOW |
| 10 | `60.2.12.12` | 5 | LOW |

---

## 3. Most Targeted Usernames

| Username | Target Frequency |
|---|---:|
| `root` | 370 |
| `admin` | 44 |
| `support` | 6 |
| `oracle` | 6 |
| `uucp` | 5 |

---

## 4. Login Events Timeline

| Timestamp | Event Type | Username | Source IP |
|---|---|---|---|
| Dec 10 06:55:48 | FAILED | `webmaster` | `173.234.31.186` |
| Dec 10 07:07:45 | FAILED | `test9` | `52.80.34.196` |
| Dec 10 07:08:30 | FAILED | `webmaster` | `173.234.31.186` |
| Dec 10 07:11:44 | FAILED | `chen` | `202.100.179.208` |
| Dec 10 07:13:43 | FAILED | `root` | `5.36.59.76` |
| Dec 10 07:13:56 | FAILED | `root` | `5.36.59.76` |
| Dec 10 07:27:52 | FAILED | `root` | `112.95.230.3` |
| Dec 10 07:27:55 | FAILED | `root` | `112.95.230.3` |
| Dec 10 07:27:58 | FAILED | `root` | `112.95.230.3` |
| Dec 10 07:28:00 | FAILED | `root` | `112.95.230.3` |

---

## 5. Security Recommendations

1. Investigate IPs with unusually high failed-login counts.
2. Prefer SSH key-based authentication.
3. Disable direct root SSH login where appropriate.
4. Monitor authentication logs regularly.
5. Consider rate limiting repeated login attempts.

**Note:** Risk levels are heuristic indicators, not proof of malicious activity. Log records may not represent distinct login attempts.