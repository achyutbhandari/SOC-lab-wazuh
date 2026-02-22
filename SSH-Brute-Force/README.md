# Detect Hydra SSH Brute Force Attack through Detection Rules and MITRE Mapping
This lab demonstrates detection of an SSH brute-force attack performed using Hydra and mapped to the MITRE ATT&CK sub-technique T1110.001 – Password Guessing.
The attack was simulated against an Ubuntu server monitored by Wazuh SIEM.

## Local Detection Rules
In Wazuh, local detection rules are custom rules created by security analysts to extend or enhance the platform’s default detection capabilities. Default rules detect individual security events (e.g., a single failed SSH login). However, real-world attacks often involve patterns of activity rather than isolated events. Local rules allow analysts to:
Correlate multiple related events
Define frequency-based thresholds
Increase or decrease alert severity
Reduce false positives
Detect organization-specific attack scenarios

Local rules are typically defined in:
/var/ossec/etc/rules/local_rules.xml  
They can reference existing rule IDs using if_sid, apply frequency and timeframe logic, and include MITRE ATT&CK mappings for structured threat classification.

## MITRE ATT&CK Mapping
The MITRE Corporation developed the MITRE ATT&CK framework to categorize adversary tactics and techniques based on real-world attack behavior.
Mapping detection rules to MITRE ATT&CK provides:
- Standardized threat classification
- Clear visibility of attacker tactics and techniques
- Improved SOC reporting and dashboards
- Alignment with industry security standards
- Better threat hunting and incident response

In Wazuh, MITRE mapping can be added directly within a rule using:

```
<mitre>
  <id>TXXXX</id>
</mitre>
```
This ensures that alerts are associated with specific ATT&CK techniques, making detection more contextual and meaningful.

## Lab Environment
- Attacker Machine: Kali Linux
- Target Machine: Ubuntu (SSH enabled)
- SIEM Platform: Wazuh
- Service Targeted: OpenSSH (Port 22)

## Attack Simulation
### Tool Used
 Hydra
## Local Detection Rules and Mitre Mapping
Wazuh default rule 5710 detected individual SSH authentication failures.
A custom rule was created to detect multiple failed login attempts within a short timeframe, indicating a brute-force attack. Detect SSH brute-force login attempts from attacker machine to target using Wazuh and map alerts to MITRE ATT&CK.
### Rule
Below are the custom rules I created and tested in this lab.
Custom rules location:
/var/ossec/etc/rules/local_rules.xml
```
<group name="local,ssh,bruteforce">
  <rule id="100100" level="12">
    <if_sid>5710</if_sid>
    <description>Custom: SSH Brute Force Attack Detected</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```
MITRE Mapping
Technique	Description
T1110	Brute Force
![Local Detection Rules for SSH Brute Force attack and Mitre Mapping](../ssh_brute_force_detection_rules_and_mitre_mapping)

### Command Executed
hydra -l achyut -P rockyou.txt ssh://192.168.10.6
### Attack Behavior
- Multiple password attempts
- Targeting a single user account (achyut)
- Live authentication attempts over SSH
- Rapid login failures in short timeframe

## Log Evidence (Ubuntu Server)
### Logs monitored:
/var/log/auth.log
Example log entries:
![Local Detection Rules for SSH Brute Force attack and Mitre Mapping](../ssh/mitre_of_ssh_brute_force_attack
)
These repeated authentication failures indicate brute-force behavior.

## MITRE ATT&CK Mapping
This activity is mapped to:
- Framework: MITRE ATT&CK
- Tactic: Credential Access
- Technique: T1110 – Brute Force
- Sub-Technique: T1110.001 – Password Guessing
**Why T1110.001?**
The attack:
- Attempts multiple passwords
- Against a single account
- Through an online authentication service (SSH)
This matches the MITRE definition of Password Guessing, which involves guessing passwords for a specific account via repeated login attempts.
________________________________________
## Detection in Wazuh
### Wazuh detected:
•	Rule 5710 – SSH authentication failure
•	Frequency-based custom rule for brute-force pattern
•	MITRE mapping included in detection rule
Example MITRE mapping in rule:  
```
<mitre>
  <id>T1110.001</id>
</mitre>
```

Failed password for achyut from 192.168.10.8 port 38508 ssh2
Accepted password for achyut from 192.168.10.8

## MITRE ATT&CK Mapping
Activity	Technique	Tactic
SSH brute force	T1110 – Brute Force	Credential Access
Successful login	T1078 – Valid Accounts	Initial Access

## Alert Analysis (SOC Perspective)
- Indicators of True Positive
- High frequency failed logins
- Same source IP
- Rapid attempts
- Possible successful login afterward
- Indicators of False Positive
- User mistyped password
- Few attempts only
- Known internal IP

## Mitigation & Hardening
- Disable root SSH login
- Enable Fail2Ban
- Implement SSH key authentication
- Enforce strong password policy
- Enable MFA
- Restrict SSH by IP
- Skills Demonstrated
- Log analysis (Linux auth logs)
- SIEM monitoring
- Wazuh rule creation
- MITRE ATT&CK mapping
- Brute-force detection
- SOC triage methodology
- Security hardening

In this lab, I simulated an SSH brute-force attack from Kali Linux against an Ubuntu server. The attack generated authentication failure logs monitored by Wazuh. Default rules triggered alerts, and I created a custom rule to detect 5 failed attempts within 60 seconds. I mapped the activity to MITRE ATT&CK T1110 and performed alert triage to differentiate between true positives and false positives.
