# Incident Reponse in Azure Sentinel Using NIST 800-61
## Introduction
In this project, the aim was to emulate the work of an SOC Analyst. Incident tickets where opened and investigated, and I tried to determine whether the incidents were legitimate. If so, I would either close out the incidents or escalate them as necessary.

Although there was a large volume of brute force attempts generated through the creation of the honeypots, it was rare for them to have a successful login attempt. These higher severity tickets where generated through the use of powershell scripts, except for the one Linux brute force success which was a true positive.
## Incident 1: Brute Force Success (Windows)
**Step 2: Detection and Analysis**

CUSTOM: Brute Force SUCCESS - Windows

Incident ID 190

- Incident was triggered on 05/09/2023 3:39 pm
- Affected Machine: windows-vm
- AttackerIP: 188.128.73.66 (Yekaterinburg, Russia)
- Attacker entity failed 5 previous brute attempts earlier in the day before the final successful attempt.
- Potentially comprised system ‘windows-vm’ involved in several other incidents/alerts. Possible overexposure to public internet
- Inspected actions from 188.128.73.66, there were 12 “successes” from the MOVS/Anonymous account but upon further investigation it was found that the alert raised was a false positive created by a service account.
- After the “successes” the attacker continued brute force attempts at the system, which suggests that they had not gained any significant access to user/admin accounts in Azure AD, such as “labuser”.
- Although a false positive was generated, we still have a medium level issue to resolve since this type of traffic should not be reaching the windows-vm in the first place.
- Closing out incident as false positive but will start the process for hardening NSGs.

**Step 3: Containment, Eradication and Recovery**

- Lock down the network security group assigned to the windows-vm and subnet by only allowing traffic from known IP Addresses that you will be accessing your VPC from.
- Enable MFA for all user accounts in Azure AD.
## Incident 2: Possible Privilege Escalation (Azure Active Directory)
## Incident 3: Brute Force Success (Linux)
## Incident 4: Malware Detected
