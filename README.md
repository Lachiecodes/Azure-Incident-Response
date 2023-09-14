# Incident Reponse in Azure Sentinel Using NIST 800-61
## Introduction
In this project, the aim was to emulate the work of an SOC Analyst. Incident tickets where opened and investigated, and I tried to determine whether the incidents were legitimate. If so, I would either close out the incidents or escalate them as necessary. This proccess was carried out using the NIST 800-61 as a framework for the incident reponse process.

Although there was a large volume of brute force attempts generated through the creation of the honeypots, it was rare for them to have a successful login attempt. These higher severity tickets where generated through the use of powershell scripts, except for the one Linux brute force success which was a true positive.

## NIST 800-61 Incident Response Framework

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
- 
## Incident 2: Possible Privilege Escalation (Azure Active Directory)
**Step 2: Detection and Analysis**

CUSTOM: Possible Privilege Escalation (Azure Key Vault Critical Credential Retrieval or Update)

Incident ID 231

- Incident was triggered on 05/09/2023 10:24pm
- Same user viewed critical credentials several times:

Name - Lachlan Simpson

User Principal Name - lachie.simpson_hotmail.com#EXT#@lachiesimpsonhotmail.onmicrosoft.com

- Not only did this user view the critical credentials multiple times, they also are involved in several other incidents including excessive password resets and global admin role assignment
- After calling the above user, they confirmed that they were just doing their normal duties, corroborated this with their manager. Closing out for benign positive.
## Incident 3: Brute Force Success (Linux)
**Step 2: Detection and Analysis**

CUSTOM: Brute Force SUCCESS - Linux Syslog

Incident ID 262

- Incident was triggered on 06/09/2023 10:14am
- Attacker at IP Address 1.157.141.118 involved in several other incidents.
- Several alerts have triggered and incidents have been automatically created based on action from this IP address.
- These incidents include several failed brute force attempts on Linux Syslog, a number of failed Azure AD brute force attempts and one successful Azure AD brute force login.
- The event was confirmed to be a true positive through querying the attacker IP address in Syslog logs.

**Step 3: Containment, Eradication and Recovery**

Initial response actions:

- The origin of the attacks was determined to be 1.157.141.118 and it was confirmed that this IP has been involved other brute force attacks on Azure AD.
- This event occurred to network security groups not being properly configured and is currently wide open to the public internet.
- The affected machine was immediately de-allocated to isolate it from the VPC

This event was remediated by:

- Resetting the password for the compromised user.
- Lock down the network security group assigned to the linux-vm and subnet by only allowing traffic from known IP Addresses that you will be accessing your VPC from.

Impact:

- Account was local to the linux machine, non-admin, essentially low impact. However, attacker involved in many other incidents. These will be remediated through NSG hardening
## Incident 4: Malware Detected
**Step 2: Detection and Analysis**

CUSTOM: Malware Detected

Incident ID 259

- Incident was triggered on 06/09/2023 9:34am
- The host machine affected was windows-vm
- Several other security alerts have been associated with this VM.
- As far as malware goes, this alert was a false positive because it looks like the user was testing with EICAR files.
- Here is the KQL query we used:

SecurityAlert
| where AlertType == "AntimalwareActionTaken"
| where CompromisedEntity == "windows-vm"
| where RemediationSteps !has "No user action necessary"

- Corroborated with user and user manager to determine if this false positive checks out with them. They confirmed that they were testing the anti-malware software on the machine.
- Closed out ticket as false positive.
