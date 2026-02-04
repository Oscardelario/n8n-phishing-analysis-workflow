# 🛡️ Automated Phishing Analysis with n8n

This repository contains an **n8n workflow** that automates the detection and analysis of potential phishing emails.  
It extracts URLs from incoming messages and evaluates them using industry-standard threat intelligence tools such as **URLScan.io** and **VirusTotal**.

The automation continuously monitors an email inbox, analyzes suspicious content, and notifies security teams with actionable intelligence in near real time.

---

## 🔄 How It Works

### Trigger Execution
The workflow can be started manually or executed on a scheduled basis using the **n8n Schedule Trigger**.

### Email Ingestion
The workflow connects to **Microsoft Outlook** and retrieves all unread emails.  
Each processed message is marked as read to prevent duplicate analysis.

> The email provider can be replaced with any other supported service.

### Batch Processing
Emails are processed one at a time using **Split In Batches**, ensuring scalability and controlled execution.

### Indicator of Compromise (IoC) Extraction
A **Python code node** analyzes the email content to extract Indicators of Compromise (IoCs), focusing primarily on URLs commonly used in phishing attacks.

### URL Validation
Emails without URLs are skipped.  
URLs found in the message body continue through the analysis pipeline.

### Threat Intelligence Analysis

- **URLScan.io** is used to scan and analyze the behavior and reputation of the extracted URLs.
- **VirusTotal** scans the same URLs across multiple security engines to identify malicious or suspicious indicators.

### Report Correlation
Results from URLScan.io and VirusTotal are merged to provide a unified, multi-layered security assessment.

### Security Notification
Once the analysis is complete, a detailed report is sent to **Slack**, including:
- Email metadata (subject, sender, date)
- Direct links to URLScan.io and VirusTotal reports
- A summarized verdict showing malicious and suspicious detections

---

## 🎯 Purpose

This workflow acts as an **automated phishing analysis pipeline**, reducing manual investigation effort and enabling faster response to email-based threats.

It is well suited for:
- SOC teams  
- Security engineers  
- Organizations looking to enhance phishing detection through automation
