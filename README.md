# OpenSSH-Security-Log-Analysis-in-Splunk
# EXECUTIVE SUMMARY

I analyzed an OpenSSH log file to identify potential security threats to an organization that had recently experienced suspicious activity. My primary objectives were to detect and monitor indicators such as unusual IP addresses, multiple failed login attempts, and other suspicious patterns.

Using Splunk Cloud, I uploaded and processed the log file, uncovering patterns including repeated authentication failures, invalid user access attempts, and high volumes of login failures from specific IPs (e.g., 183.62.140.253). I also identified disconnect messages (Bye Bye [preauth]) linked to multiple IPs originating from different geolocations.

The behavioral patterns indicated probable brute-force attempts via automated scanning botnets or unauthorized probes. To address this, I developed a Splunk dashboard and configured an alerting system to detect and trigger notifications for potential brute-force or unauthorized access attempts. Additionally, I reviewed and implemented user role configurations based on the principle of least privilege to strengthen access control.

## USER CREATION AND ROLE MANAGEMENT

As part of the security configuration in Splunk Cloud, I created and managed user accounts with clearly defined roles and access capabilities:

*   2 Admin users with full privileges
*   5 Power users with elevated analysis and search capabilities
*   2 Standard users with restricted access

The objective was to ensure proper access control, validate role assignments, and support internal audits and compliance requirements.

During account setup, I implemented the following configurations:

*   **Time Zone Alignment:** Set all users to West Africa Time (WAT) to maintain consistency in event timestamps.
*   **Default Application:** Configured the Launcher (Home) as the default application for a uniform post-login experience.
*   **Password Policy Enforcement:** Required all users to change their password upon first login to enhance account security.

This approach ensured a principle of least privilege was applied, reduced unauthorized access risk, and improved audit readiness.

## ANALYSIS OF OPENSSH LOG FILE

The OpenSSH log file was manually uploaded into Splunk Cloud to enable efficient search, filtering, and analysis. Upload parameters were configured as follows:

*   **Source:** OpenSSH.csv — the file source for Splunk ingestion.
*   **Sourcetype:** csv — defining the file format for accurate parsing.
*   **Index:** main — the storage location within Splunk (similar to a database).

The dataset contained approximately **2,000 events**. Key observation features included:

*   Failed Login Attempts
*   Disconnection Events
*   External IP Addresses
*   Timestamps
*   IP Geolocation Data

These event patterns were instrumental in identifying potential attack signatures and prioritizing response actions.

![Img ](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/a692a875d786b2a66b001010a44d6044dd57fa9a/ossh%201.jpg)

![Img](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/137cd29737753bb21b9be57add801b4d69338542/ossh%202.jpg)

## ANALYSIS BY TIMESTAMP

I grouped log events into **5-minute intervals** to observe activity spikes and patterns. The analysis counted how many failed login attempts each remote host (rhost) generated in a given 5-minute window, filtering only IPs with **more than 5 attempts** in any interval. Results were sorted in descending order by time to prioritize the latest suspicious activity.

Key findings included:

*   **IP 183.62.140.253** – highly aggressive, making **129–141 login attempts** within several 5-minute intervals.
*   **IPs 103.99.0.122, 187.141.143.180, and 112.195.230.3** — repeatedly attempting logins at abnormal rates.

These are not normal user behaviors Such high-frequency login attempts strongly suggest brute-force or automated scanning activity rather than normal user behavior.

![Image Below ](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/a692a875d786b2a66b001010a44d6044dd57fa9a/ossh%203.jpg)

## ANALYSIS BY GEOLOCATION
A total of 496 failed SSH authentication attempts originated from non-Nigerian IP addresses. Source IPs were mapped to countries commonly associated with botnet or brute-force activity.
Findings included:
China — over 300 combined attempts from multiple cities (Beijing, Shenzhen, Weifang, Langfang).
Mexico and Vietnam — significant volumes of login attempts.
The dataset was filtered to exclude internal/Nigerian IPs, reinforcing that these were likely unauthorized foreign intrusion attempts.

![Image Below ](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/a692a875d786b2a66b001010a44d6044dd57fa9a/ossh%204.jpg)

## ANALYSIS BY USERS 
I analyzed failed SSH login attempts from the OpenSSH logs to determine the most frequently targeted usernames. The result  states root was the primary target accounting for 74.3% of all failed attempts. Other usernames like uucp, ftp, mysql, and git are common service accounts. 
The heavy targeting of root suggests an active brute-force attack aiming for administrative access. Attempts on service accounts indicate automated scans or credential stuffing using known usernames. These patterns are typical of external threat actors probing for vulnerable systems. 

![Image Below ](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/a692a875d786b2a66b001010a44d6044dd57fa9a/ossh%205.jpg)

## ANALYSIS BY MULTIPLE FAILED ATTEMPTS  
To identify the source IP addresses (rhost) responsible for the highest number of failed SSH login 
attempts, I ran the following Splunk query: 
index="main" source="OpenSSH.csv" "authentication failure" 
| rex "rhost=(?<rhost>\d{1,3}(?:\.\d{1,3}){3})" 
| stats count by rhost 
| sort –count 
From this analysis: 
 IP 183.62.140.253 emerged as the most aggressive attacker, accounting for 57.8% of the 
496 total failed attempts. 
 All IPs within the 183.62.140.x subnet collectively generated 431 attempts, indicating 
either: 
o A coordinated scanning effort, or 
o A single attacker using multiple IP addresses in the same subnet. 
The repeated IP patterns and consistent failure rates align with brute-force activity or botnet
driven reconnaissance.

 ![Image Below ](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/59fc80e4f690d76a3c111ab650cdecec52209175/ossh%206.jpg)

 ## DASHBOARD CONFIGURATION 
I created a Splunk dashboard to monitor high-frequency disconnect events originating from the IP address 112.95.230.3. The repetitive disconnection pattern and timing indicated that an external system was repeatedly attempting to establish SSH connections but was disconnected before authentication ([preauth]).
The consistent nature of these disconnection events suggests potential network scanning or brute-force attack behavior. The dashboard visualized these events in real time, providing an early warning mechanism for rapid detection and investigation of similar suspicious activity.

![Image Below ](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/59fc80e4f690d76a3c111ab650cdecec52209175/ossh%207.jpg)

## ALERT CONFIGURATION 
To complement the dashboard, I implemented an automated alert system in Splunk with the following configuration:
•	Schedule: Runs daily at 08:00 AM (WAT)
•	Alert Expiration: Expires after 24 hours
•	Trigger Condition: Fires when the number of matching results is greater than 2
•	Notification Type: Plain-text email
•	Recipients: Designated approved recipients within a specified domain
•	Domain Restriction: Email delivery restricted to approved domains only (e.g., gmail.com) to enhance security and limit alert visibility
Purpose of the alert:
•	Detect and notify on suspicious SSH disconnect events
•	Identify potential brute-force attempts or automated login failures
•	Monitor for network scanning or reconnaissance activity
•	Flag abuse from malicious IP addresses (bots or unauthorized users)
•	Track unexpected session terminations on critical servers
This configuration ensured that any suspicious activity was detected promptly and shared with the right stakeholders, reducing incident response time.
  
![Image Below ](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/59fc80e4f690d76a3c111ab650cdecec52209175/ossh%208.jpg)

![Image](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/59fc80e4f690d76a3c111ab650cdecec52209175/ossh%209.jpg)

## FIELD EXTRACTION CONFIGURATION 
I configured a custom field extraction in Splunk for the src_ip field, which tracks the source hosts involved in SSH disconnect events. This field is critical for:
•	Pinpointing the origin of suspicious SSH activity
•	Informing automated defense mechanisms and blacklist rules
•	Supporting SIEM correlation for broader security monitoring
Splunk identified 95 unique values for src_ip, representing 99.95% of all events in the dataset. 

![Image Below ](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/59fc80e4f690d76a3c111ab650cdecec52209175/ossh%2010.jpg)

## CONCLUSION 
The analysis of the OpenSSH.csv logs through Splunk has revealed a high number of failed SSH authentication attempts primarily from a concentrated group of external IP addresses like 183.62.140.253 from Beijing China as the top offender with 287 login failures, several other IPs from the same subnet were also active suggesting automated or coordinated attack attempts likely brute-force in nature. Attempts were mainly directed at privileged accounts like root accounting for 74% of the total failed logins 369 out of 496, 
The source of attacks includes countries such as China, Mexico, Vietnam, Russia, and the United States, indicating global threat vectors targeting the system. 
These patterns are consistent with credential stuffing, dictionary attacks, or brute force login attempts, and if not mitigated it could lead to unauthorized system access and compromise of critical infrastructure. 

## RECOMMENDATIONS  
Based on the findings from this analysis, I recommend the following measures to strengthen SSH security and reduce the risk of unauthorized access:
Immediate Mitigation
•	Block/Blacklist Malicious IPs: Use firewall rules to block high-risk IPs, such as 183.62.140.253.
•	Disable Root Login: Prevent direct SSH login to the root account.
Access Hardening
•	Enable Rate Limiting: Deploy tools like Fail2Ban or SSHGuard to automatically block IPs with multiple failed login attempts.
•	Restrict Access via Geo-IP: Implement IP filtering to block SSH access from high-risk countries unless explicitly required for operations.
•	Use SSH Keys Instead of Passwords: Enforce public key authentication for all users to eliminate password-based attacks.
Account Security
•	Enforce Strong Password Policies: Require complex passwords and periodic password changes.
•	Limit SSH Access to Specific Users: Use AllowUsers or AllowGroups directives in the SSH configuration to restrict access.










