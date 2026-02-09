# Recon Telegram Bot

![Security](https://img.shields.io/badge/Security-Recon-yellow)


A Telegram-based reconnaissance automation bot for authorized security testing.

---

## Features
- Network discovery (Nmap)
- Full TCP port scanning
- Web technology fingerprinting (WhatWeb)
- Vulnerability scanning (Nuclei)
- Web server assessment (Nikto)
- Content discovery (Dirsearch)
- Manual and automated scan modes
- Executive Summary PDF report with severity grouping

---

## Requirements
- Python 3.10+
- Nmap
- Nuclei
- WhatWeb
- Nikto
- Dirsearch

---

## Installation

    git clone https://github.com/SandeepSis0diya/Recon-Telegram-Bot.git
    cd Recon-Telegram-Bot
    pip install -r Requirements.txt

## Configure Telegram Bot Token

## Insert your Telegram bot token in the configuration file as shown below:

<img width="774" height="49" alt="image" src="https://github.com/user-attachments/assets/ddbf336f-5782-4885-8f67-1a8c6fc79e96" /> <img width="471" height="86" alt="image" src="https://github.com/user-attachments/assets/de997ec3-e7f8-4301-91db-0d6dae127217" /> <img width="717" height="112" alt="image" src="https://github.com/user-attachments/assets/77351728-688a-458e-9c0b-0bc28350b95a" />  <br> 

## Run the Bot

        python3 Recon_bot.py

<img width="775" height="89" alt="image" src="https://github.com/user-attachments/assets/f193c1e1-37a7-4353-bb4a-a59f391bf6d5" />
Usage

## After running the bot, open Telegram and go to the bot dashboard.
## Run the following command:

    /start


## You will see multiple scanning options available.

<img width="332" height="295" alt="image" src="https://github.com/user-attachments/assets/2937eb21-47fa-4b09-9c33-f2355596106c" />
## Scan Report

## After running an automatic full scan, the bot generates a complete PDF report with all findings.

<img width="287" height="97" alt="image" src="https://github.com/user-attachments/assets/9ebcb372-d520-4834-b6a1-5a531b95d01d" />
## Disclaimer

This project is intended only for authorized security testing.
Scanning systems without explicit permission is illegal and unethical.
