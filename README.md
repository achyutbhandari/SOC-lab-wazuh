# Security Operations Home Lab – Wazuh SIEM
## Project Overview
 Wazuh SIEM Home Lab – Detection & Monitoring Lab
## Lab Overview
This project demonstrates a Wazuh SIEM home lab built to simulate real-world security monitoring, log collection, and attack detection using multiple virtual machines.  
The lab includes:
- Wazuh Manager (SIEM)
- Linux & Windows endpoints (agents)
- Kali Linux attacker machine
- Detection testing and alert analysis
This lab helped me understand SIEM architecture, log ingestion, detection rules, and incident visibility.

## Lab Architecture
- Machine	Role	IP Address
- Ubuntu Server	Wazuh Manager	192.168.10.7
- Ubuntu Desktop	Wazuh Agent	192.168.10.6
- Windows 10	Wazuh Agent	192.168.10.5
- Kali Linux	Attacker Machine	192.168.10.8
All machines are on the same virtual network.
________________________________________
## Components Used
- Wazuh Manager – log analysis, detection rules, alerting
-	Wazuh Agents – endpoint monitoring
-	OpenSearch / Wazuh Dashboard – log visualization
- Kali Linux – attack simulation
________________________________________
## Installation Summary
### Wazuh Manager Installation (Ubuntu)
Installed using official Wazuh all-in-one installer.  
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh  
sudo bash wazuh-install.sh -a  
**Services:**  
sudo systemctl status wazuh-manager  
sudo systemctl status wazuh-dashboard  
________________________________________
### Ubuntu Agent Installation
curl -sO https://packages.wazuh.com/4.x/wazuh-agent.sh
sudo bash wazuh-agent.sh -a 192.168.10.7
Start agent:
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
________________________________________
### Windows Agent Installation
1.	Download Wazuh Agent MSI.
2.	During installation set manager IP:
3.	192.168.10.7
4.	Start service:
Start-Service WazuhSvc
Check logs:
C:\Program Files (x86)\ossec-agent\logs\ossec.log
________________________________________
### Agent Registration  
Check connected agents on manager:  
sudo /var/ossec/bin/agent_control -l  
Expected output:  
Ubuntu-agent   192.168.10.6  
Windows-agent  192.168.10.5  
________________________________________
## Log Locations
Manager Logs  
Log	Path  
Wazuh logs	/var/ossec/logs/ossec.log  
Alerts	/var/ossec/logs/alerts/alerts.log  
JSON alerts	/var/ossec/logs/alerts/alerts.json  
Agent Logs  
OS	Path  
Ubuntu Agent	/var/ossec/logs/ossec.log  
Windows Agent	C:\Program Files (x86)\ossec-agent\logs\ossec.log  
________________________________________
## Attack Simulation (Kali Linux) 
Attacks were performed from 192.168.10.8 to test detection. 
________________________________________
##Detection Scenarios Tested 
### SSH Brute Force (Linux Agent) 
Command from Kali: 
hydra -l root -P rockyou.txt ssh://192.168.10.6 
Detected alerts: 
- Multiple authentication failures
- SSH brute force detection
- Possible password guessing
Log source:  
/var/ossec/alerts/alerts.log

![Brute Force Attack from Kali linux Machine to Ubuntu Machine](./screenshots/Brute%20force%20attack%20to%20ubuntu.png)


________________________________________
### Windows Suspicious Command Execution
Test command:  
Invoke-WebRequest https://secure.eicar.org/eicar.com  
Detected alerts:  
- 	Suspicious PowerShell execution
-  Malware test file download attempt

![Detect Malware file download attempt from Windows Machine](./screenshots/Milacious%20virus%20download%20detected%20logs.png)
________________________________________
### Linux Privilege Escalation Monitoring
sudo su  
Detected alerts:  
- Privilege escalation
- Sudo usage monitoring

![Privilege Escalation on Ubuntu Device Monitoring](./screenshots/Priviledge%20access%20attempt.png)
________________________________________
### File Integrity Monitoring (FIM)
Test:  
touch /etc/testfile  
Detected alerts:  
New file creation in monitored directory  
![Detected Create of New test file](./screenshots/File%20Integrity%20Monitoring.png)


## Alert Analysis
Alerts were observed using:  
sudo tail -f /var/ossec/logs/alerts/alerts.log  
Example alert:  
Rule: 5710 - SSH brute force attack detected  
Level: 10
________________________________________
## Skills Demonstrated
-	SIEM deployment & troubleshooting
-	Log ingestion & analysis
-	Endpoint security monitoring
-	Attack simulation
-	Alert triage
-	Linux & Windows log analysis
-	Networking & firewall configuration
________________________________________
## Future Improvements
-	Add Suricata IDS integration
-	Add Active Directory logs
-	Create custom Wazuh detection rules
-	Automate attack simulations
________________________________________
## Conclusion
This lab demonstrates how Wazuh can detect real attack behavior across Linux and Windows environments, providing hands-on experience in SIEM operations and SOC workflows.
