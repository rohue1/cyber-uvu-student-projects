## Birthday Memory / Security Assessment (Red Team)

A penetration test of the application Birthday Memory, which is an application that runs a React frontend, utilizes Express API, and a PostreSQL database to store user PII.
This database stores information such as names, emails, birthdates, and phone numbers.
The assessment done outlines what was exploitable from another host on the same network. This writeup documents the findings and provides a CCVS score for each one
in the findings.md report. 

Track: Read Team
Methodology: OWASP WSTG
Scope: My own fork of the repository, tested by a Kali VM using fake information on the database.

### Overall Assessment

This application should not ship. This writeup documents the attack surface and different paths an attacker could take to tamper with resources, steal PII, all while doing
so undetected. The Express API can be reached by anyone on the same network as the server running this application, the database has a default user and password that is 
easy to guess, and the application is running as a privileged user. Below I have documented my findings in the application:

- Unauthenticated read / create / modify / destroy of records | Severity: High
- No authentication or authorization layer exists at all | Severity: Criticial
- Default DB credentials committed to the repo | Severity: Critical
- PII unencrypted at rest, DB connection plaintext | Severity: Medium
- No logging audit trail for create / modify / destroy | Severity: Medium
- Container runs as root with full default configurations | Severity : Medium
- 22 High and 1 Critical CVE found in the image | Severity : Critical 
- No "Zero Trust" design posture | Severity : Critical

There were two categories that were found Not Vulnerable:
- SQL injection: Queries were parameterized and inputs were validated in the source code.
- SSRF: Not applicable since endpoint does not take URL inputs or make user controlled outbound requests.

### Evidence

Each finding has reproduceable evidence located in the security/evidence directory with proper lableing. The evidence set was generated using a script I created with the help of Claude AI:
python3 security/capture-evidence.py

findings.md: This is the findings register with CVSS 3.1 scores
security/baseline: This is the baseline configuration of the application before any testing was done. 

### AI Usage

AI usage was permitted for this lab. I used Claude AI to help review any findings I made, along with creating the script to generate the evidence saved in this repository. 
Claude caught errors in my reasoning and verified any syntax errors I ran into, and helped scaffold the script that I designed. Claude also formatted the assessment write up
for readability.  
All of the actual testing, findings, evidence was done by me. 

### Scope

Testing was done on my own fork of the repository using a local Kali VM on my machine, seeded with fake information. No personal data was used and no UVU machine or third-party
asset was touched during testing. 


