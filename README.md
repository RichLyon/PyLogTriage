Log Analysis and Alert System
Table of Contents
Overview
Features
Prerequisites
Installation
Configuration
Usage
How It Works
Contributing
License
Overview
This Log Analysis and Alert System is a Python-based tool designed to continuously monitor log files for suspicious activities and potential security threats. When detected, it sends email alerts to specified recipients using Gmail's API. The system leverages the Ollama AI model for advanced log analysis.

Features
Continuous monitoring of multiple log files
AI-powered log analysis using Ollama
Email alerts for detected suspicious activities
Integration with Gmail API for sending alerts
Resumable log processing (tracks last read position)
Configurable through environment variables
Prerequisites
Before you begin, ensure you have met the following requirements:

Python 3.6+
Ollama installed and configured with the ALIENTELLIGENCE/cybersecuritythreatanalysis:latest model
A Google Cloud Project with Gmail API enabled
OAuth 2.0 Client ID credentials from Google Cloud Console
Installation
Clone the repository:

git clone https://github.com/yourusername/log-analysis-alert-system.git
cd log-analysis-alert-system
Install the required Python packages:

pip install -r requirements.txt
Set up your Google Cloud Project and obtain the OAuth 2.0 credentials:

Go to the Google Cloud Console
Create a new project or select an existing one
Enable the Gmail API for your project
Create OAuth 2.0 Client ID credentials
Download the credentials JSON file and save it as credentials.json in the project directory
Configuration
Create a .env file in the project root directory with the following contents:

EMAIL_ADDRESS=your-email@example.com
LOG_DIRECTORY=/path/to/your/log/directory
Replace the values with your actual email address and the directory containing the log files you want to monitor.

Ensure that the credentials.json file is in the project root directory.

Usage
To start the Log Analysis and Alert System, run:

python app.py
The system will start monitoring the specified log directory, analyze new log entries every 2 hours, and send email alerts if suspicious activities are detected.

How It Works
Log File Discovery: The system scans the specified LOG_DIRECTORY for .log files.

Incremental Processing: For each log file, the system keeps track of the last processed position to avoid reanalyzing the same data.

AI-Powered Analysis: New log entries are sent to the Ollama AI model for analysis. The model is prompted to identify suspicious activities, potential threats, and provide security recommendations.

Alert Generation: If the AI analysis detects suspicious activities or threats, an email alert is generated.

Email Notification: Alerts are sent via Gmail using the Gmail API. The system authenticates using OAuth 2.0.

Continuous Monitoring: The process repeats every 2 hours, ensuring ongoing surveillance of log files.

Contributing
Contributions to this project are welcome. Please follow these steps:

Fork the repository
Create a new branch (git checkout -b feature/your-feature-name)
Make your changes and commit them (git commit -am 'Add some feature')
Push to the branch (git push origin feature/your-feature-name)
Create a new Pull Request
License
This project is licensed under the MIT License - see the LICENSE file for details.
