import os
import subprocess
import base64
import time
import json
from email.mime.text import MIMEText
from datetime import datetime

from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from dotenv import load_dotenv

load_dotenv()

# Load environment variables
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
LOG_DIRECTORY = os.getenv('LOG_DIRECTORY')

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# File to store the last processed positions
LAST_POSITIONS_FILE = 'last_positions.json'


def get_gmail_service():
    print("Initializing Gmail service...")
    creds = None

    if os.path.exists('token.json'):
        try:
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
            print("Credentials loaded from token.json")
        except Exception as e:
            print(f"Error loading credentials: {e}")
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                print("Credentials refreshed")
            except Exception as e:
                print(f"Error refreshing credentials: {e}")
                return None
        else:
            try:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
                print("Credentials obtained from user authentication flow")
            except Exception as e:
                print(f"Error during authentication flow: {e}")
                return None

        with open('token.json', 'w') as token:
            token.write(creds.to_json())
            print("Credentials saved to token.json")

    try:
        service = build('gmail', 'v1', credentials=creds)
        print("Gmail service successfully built")
        return service
    except Exception as e:
        print(f"Error building Gmail service: {e}")
        return None


def send_email(service, to_email, subject, message_text):
    print(f"Sending email to {to_email} with subject: '{subject}'")
    try:
        message = MIMEText(message_text)
        message['to'] = to_email
        message['from'] = 'me'  # 'me' refers to the authenticated user
        message['subject'] = subject
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        message_body = {'raw': raw_message}

        sent_message = (service.users().messages().send(userId='me', body=message_body).execute())
        print(f'Message sent successfully. Message Id: {sent_message["id"]}')
        return sent_message
    except Exception as e:
        print(f"Error sending email: {e}")
        return None


def analyze_log_with_ollama(log_text):
    print("Analyzing log with Ollama...")
    prompt = """
        You are analyzing a log file for cybersecurity threats. Your analysis should include the following:
        1. Any suspicious activities detected
        2. Potential threats identified
        3. Any recommendations for improving security
        4. Any other observations

        Don't forget to include the log lines that led you to your conclusions.
        Be as detailed as possible to ensure the security team can take appropriate action.

    """

    try:
        process = subprocess.Popen(
            ['ollama', 'run', 'ALIENTELLIGENCE/cybersecuritythreatanalysis:latest'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        stdout, stderr = process.communicate(input=prompt)

        if process.returncode != 0:
            print(f'Error running Ollama (Return Code {process.returncode}): {stderr}')
            return None
        else:
            print("Log analysis completed successfully")
            return stdout.strip()
    except Exception as e:
        print(f"Error running Ollama subprocess: {e}")
        return None


def get_log_files(directory):
    print(f"Retrieving log files from directory: {directory}")
    log_files = []
    try:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.lower().endswith('.log'):
                    full_path = os.path.join(root, file)
                    log_files.append(full_path)
                    print(f"Found log file: {full_path}")
    except Exception as e:
        print(f"Error retrieving log files: {e}")

    print(f"Total log files retrieved: {len(log_files)}")
    return log_files


def load_last_positions():
    if os.path.exists(LAST_POSITIONS_FILE):
        with open(LAST_POSITIONS_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_last_positions(positions):
    with open(LAST_POSITIONS_FILE, 'w') as f:
        json.dump(positions, f)


def get_new_lines(file_path, last_position, max_lines=1000):
    try:
        with open(file_path, 'r') as file:
            file.seek(0, 2)  # Move to the end of the file
            file_size = file.tell()

            if last_position > file_size:
                # File has been truncated, start from the beginning
                last_position = 0

            if file_size > last_position:
                # There's new content
                file.seek(-min(file_size, file_size - last_position), 2)
                lines = file.readlines()

                # Get the last max_lines
                new_lines = lines[-max_lines:]
                new_position = file_size

                return ''.join(new_lines), new_position
            else:
                # No new content
                return '', last_position
    except Exception as e:
        print(f"Error reading log file {file_path}: {e}")
        return '', last_position


def analyze_logs(max_lines=1000):
    log_directory = LOG_DIRECTORY
    print(f"Starting log analysis for directory: {log_directory}")

    if not os.path.exists(log_directory):
        print(f'Log directory not found at {log_directory}')
        return

    log_files = get_log_files(log_directory)

    if not log_files:
        print(f'No log files found in {log_directory}')
        return

    service = get_gmail_service()
    if not service:
        print('Failed to initialize Gmail service')
        return

    last_positions = load_last_positions()

    for log_file in log_files:
        print(f'Analyzing log file: {log_file}')
        last_position = last_positions.get(log_file, 0)
        new_lines, new_position = get_new_lines(log_file, last_position, max_lines)

        if not new_lines:
            print(f'No new content to analyze in file: {log_file}')
            continue

        analysis_result = analyze_log_with_ollama(new_lines)

        if analysis_result is None:
            print(f'Failed to analyze log file: {log_file}')
            continue

        # Check if the analysis result indicates a suspicious activity
        if "suspicious" in analysis_result.lower() or "threat" in analysis_result.lower():
            subject = f'Suspicious Activity Detected in {os.path.basename(log_file)}'
            message_text = f'Analysis for {log_file}:\n{analysis_result}\n\n'
            send_email(service, EMAIL_ADDRESS, subject, message_text)
            print(f"Sent alert email for suspicious activity in {log_file}")

        last_positions[log_file] = new_position

    save_last_positions(last_positions)


def main():
    try:
        while True:
            print("Starting log analysis cycle")
            analyze_logs(max_lines=1000)  # Analyze the last 1000 lines of each log file
            print(f"Sleeping for 2 hours...")
            time.sleep(2 * 60 * 60)  # Sleep for 2 hours
    except KeyboardInterrupt:
        print("Program terminated by user.")


if __name__ == '__main__':
    main()