# NetSecure – Real-Time Network Security Monitor



### Overview

NetSecure is a real-time network monitoring and alert system built in Python.  

It captures live network traffic, analyzes it for suspicious activity such as port scanning, ARP spoofing, and flood attacks, and displays the results through an interactive graphical dashboard.



This project was developed to help users visualize, detect, and respond to potential intrusions in real time — making it ideal for cybersecurity learners and professionals who want hands-on experience with network defense.

###### 

### Features

* Live Packet Capture: Monitors real-time traffic using the Scapy library.
* Anomaly Detection: Detects port scans, flood attacks, and ARP spoofing.
* Threat Intelligence Integration: Checks IP reputation using the AbuseIPDB API.
* Automated Alerts: Sends email or Slack notifications for detected threats.
* Graphical Dashboard: Built with Tkinter and Matplotlib for real-time visualization.
* Local Database Logging: Stores packets and alerts in an SQLite database for later review.



#### Tools \& Technologies

Language:\*\* Python 3  



Libraries Used:

&nbsp; `scapy` – Packet sniffing and analysis  

&nbsp; `sqlite3` – Database logging  

&nbsp; `tkinter` – Graphical interface  

&nbsp; `matplotlib` – Live data visualization  

&nbsp; `requests` – API integration  

&nbsp; `smtplib` – Email alerts  



Database: SQLite  

API Integration: AbuseIPDB  

Platform Compatibility: Windows and Linux



#### Installation



Prerequisites

Make sure you have \*\*Python 3.x\*\* installed along with `pip`.



Clone the Repository

bash

git clone https://github.com/SushilDixith/NetSecure.git

cd NetSecure

pip install requirements.txt -r




