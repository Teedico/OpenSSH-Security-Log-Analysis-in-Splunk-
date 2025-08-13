# OpenSSH-Security-Log-Analysis-in-Splunk
# EXECUTIVE SUMMARY

I analyzed an OpenSSH log file to identify potential security threats to an organization that had recently experienced suspicious activity. My primary objectives were to detect and monitor indicators such as unusual IP addresses, multiple failed login attempts, and other suspicious patterns.

Using Splunk Cloud, I uploaded and processed the log file, uncovering patterns including repeated authentication failures, invalid user access attempts, and high volumes of login failures from specific IPs (e.g., 183.62.140.253). I also identified disconnect messages (Bye Bye [preauth]) linked to multiple IPs originating from different geolocations.

The behavioral patterns indicated probable brute-force attempts via automated scanning botnets or unauthorized probes. To address this, I developed a **Splunk dashboard** and configured an **alerting system** to detect and trigger notifications for potential brute-force or unauthorized access attempts. Additionally, I reviewed and implemented **user role configurations** based on the principle of least privilege to strengthen access control.

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

This approach ensured a **principle of least privilege** was applied, reduced unauthorized access risk, and improved audit readiness.

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

## ANALYSIS BY TIMESTAMP

I grouped log events into **5-minute intervals** to observe activity spikes and patterns. The analysis counted how many failed login attempts each remote host (rhost) generated in a given 5-minute window, filtering only IPs with **more than 5 attempts** in any interval. Results were sorted in descending order by time to prioritize the latest suspicious activity.

Key findings included:

*   **IP 183.62.140.253** – highly aggressive, making **129–141 login attempts** within several 5-minute intervals.
*   **IPs 103.99.0.122, 187.141.143.180, and 112.195.230.3** — repeatedly attempting logins at abnormal rates.

These are not normal user behaviors Such high-frequency login attempts strongly suggest **brute-force or automated scanning activity** rather than normal user behavior.
