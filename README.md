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

![Img](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/a692a875d786b2a66b001010a44d6044dd57fa9a/ossh%202.jpg)

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

 ![Image Below ](https://github.com/Teedico/OpenSSH-Security-Log-Analysis-in-Splunk-/blob/a692a875d786b2a66b001010a44d6044dd57fa9a/ossh%206.jpg)


