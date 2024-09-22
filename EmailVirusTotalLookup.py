import imaplib
import email
from email.header import decode_header
import os
from dotenv import load_dotenv
import re
import ipaddress
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import csv

# Sets username and password for IMAP server login from .env file, rather than hardcoding credentials in script. Also pulls VirusTotal API key.

path_for_email_creds = ('EmailCreds.env')
load_dotenv(path_for_email_creds)
username = os.getenv("EMAIL_USER")
password = os.getenv("EMAIL_PASS")
VTAPI = os.getenv("VT_API")


# Connect to email server.
 
def connect_to_email(username, password):

    # Connects to internal IMAP server
    server = imaplib.IMAP4_SSL("emailserver.emaildomain")

    # Login to the server
    server.login(username, password)
    return server

# Fetch emails from inbox

def fetch_emails(server):
    server.select("inbox") # Selects mailbox that alerts are received in
    status, messages = server.search(None, "ALL") # Searches all emails
    email_ids = messages[0].split() # Get's list of email IDs
    return email_ids

# Decode subjects of emails

def get_email_subject(email_message):
    subject, encoding = decode_header(email_message["Subject"])[0]
    if isinstance(subect, bytes):

        # Decode's byte format, if necessary
        subject = subject.decode(encoding if encoding else "utf-8")
    return subject

# Fetch and print the subject of emails

def print_email_subjects(server):
    email_ids = fetch_emails(server)
    for email_id in email_ids[:5]: # Limits to first 5 emails
        status, msg_data = server.fetch(email_id, "(RFC822)") # Fetches email data
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                email_message = email.message_from_bytes(response_part[1])
                subject = get_email_subject(email_message)
                print(f"Email Subject: {subject}")

# Fetch and print body of emails

def print_email_bodies(server):
    email_ids = fetch_emails(server)
    for email_id in email_ids[:5]:  # Limit to first 5
        status, msg_data = server.fetch(email_id, "(RFC822)")  # Fetch email data
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                email_message = email.message_from_bytes(response_part[1])
                subject = get_email_subject(email_message)
                print(f"Email Subject: {subject}")
                
                # Get and print the body
                body = get_email_body(email_message)
                print(f"Email Body: {body}...")  # Limit to first 100 characters for display


# Read body of the email

def get_email_body(email_message):
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" not in content_disposition:
                if content_type == "text/plain": # Plain text emails
                    return part.get_payload(decode=True).decode("utf-8")
                elif content_type == "text/html": # HTML Emails
                    return part.get_payload(decode=True).decode("utf-8")
    else:
        return email_message.get_payload(decode=TRUE).decode("utf-8")


# Function to extract IP addresses from the email body using regular expression

def extract_ips_from_email(body):

    # RE pattern for finding an IP address
    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    # This finds the source IP and destination IP
    source_ip_match = re.search(r"Source IP:\s*" + ip_pattern, body)
    destination_ip_match = re.search(r"Destination IP:\s*" + ip_pattern, body)

    # If IP address is found, extract the IPs, otherwise returns None
    source_ip = source_ip_match.group(1) if source_ip_match else None
    destination_ip = destination_ip_match.group(1) if destination_ip_match else None

    return source_ip, destination_ip

# Function to check if an IP address is private

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)  # Create an IP address object
        return ip_obj.is_private  # Return True if the IP is private

# Function to query VirusTotal for an IP address

def check_ip_with_virustotal(ip, api_key):
    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {"apikey": api_key, "ip": ip}
    response = requests.get(url, params=params)

    if response.status_code == 200:
        data = response.json()
        if 'detected_urls' in data and len(data['detected_urls']) > 0:
            print(f"IP {ip} is associated with malicious activity.")
        else:
            print(f"IP {ip} is not associated with malicious activity.")
    else:
        print(f"Error querying VirusTotal for IP {ip}: {response.status_code}")
                             
# Function to send an email using SMTP

def send_email(to_address, subject, body, smtp_server, smtp_port, username, password):
    msg = MIMEMultipart()
    msg['From'] = username
    msg['To'] = to_address
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    # Connect to the SMTP server and send the email
    
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()  # Secure the connection
    server.login(username, password)
    server.sendmail(username, to_address, msg.as_string())
    server.quit()

# Appends malicious IP address to csv file used by firewall as blocklist

def append_to_csv(ip, status, data):
    csv_file = 'malicious_ips.csv'
    # Define the headers
    headers = ['IP', 'Status', 'VirusTotal Data']

    with open(csv_file, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        
        if file.tell() == 0:
            writer.writerow(headers)
            
        writer.writerow([ip, status, str(data)])

    print(f"Logged {ip} to {csv_file}")

# Defines main function

def main():
    server = connect_to_email(username, password)
    email_ids = fetch_emails(server)
    report = ""
    for email_id in email_ids[:5]:
        status, msg_data = server.fetch(email_id, "(RFC822)")
        
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                email_message = email.message_from_bytes(response_part[1])
                body = get_email_body(email_message)
                source_ip, destination_ip = extract_ips_from_email(body)
                if source_ip and not is_private_ip(source_ip):
                    report += f"Source IP {source_ip}: {check_ip_with_virustotal(source_ip, VTAPI)}\n"
                
                if destination_ip and not is_private_ip(destination_ip):
                    report += f"Destination IP {destination_ip}: {check_ip_with_virustotal(destination_ip, VTAPI)}\n"
    
    if report:
        send_email(
            to_address=username,
            subject="IP Address Report",
            body=report,
            smtp_server="emailserver.emaildomain",
            smtp_port=587,
            username=username,
            password=password
        )
        print("Report sent successfully!")
    else:
        print("No public IPs found or no VirusTotal reports generated.")
    
    server.logout()

# Run the main function
if __name__ == "__main__":
    main() 
