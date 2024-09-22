Email IP Scanner and VirusTotal Checker
This Python project automates the process of scanning security alert emails for IP addresses, checking them against the VirusTotal API for potential malicious activity, and generating a report. The script:

Connects to an email inbox using IMAP.
Fetches email bodies and extracts IP addresses (e.g., Source IP and Destination IP).
Checks public IPs with VirusTotal for any suspicious activity or known malicious associations.
Logs the results into a CSV file, categorizing IPs as either "Malicious" or "Clean." This file can be used as a blocklist a firewall uses, allowing for automatic blocking of malicious IP addresses.
Sends an email report summarizing the findings.
The script can be used as a simple security tool to monitor and report on potentially harmful IP addresses found in emails, as well as automatically block malicious traffic.

Features
Connects to an IMAP server to retrieve emails.
Extracts and validates IP addresses using regular expressions.
Checks IP reputation using VirusTotal API.
Logs IP addresses and their VirusTotal status to a CSV file.
Sends a summary email with the results.
Requirements
Python 3.x
IMAP access to the email account
VirusTotal API key
