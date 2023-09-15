# Incident Response in Azure Sentinel Using NIST 800-61
## Introduction
In this project, the aim was to emulate the work of a SOC Analyst. Incident tickets were opened and investigated, and I tried to determine whether the incidents were legitimate. If so, I would either close out the incidents or escalate them as necessary. This process was carried out using the NIST 800-61 as a framework for the incident response process.

Although there was a large volume of brute force attempts generated through the creation of the honeypots, it was rare for them to have a successful login attempt. These higher severity tickets were generated through the use of PowerShell scripts, except for the one Linux brute force success, which was a true positive.

## NIST 800-61 Incident Response Framework
![Screenshot 2023-09-14 222035](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/0c2e01e8-eca0-4630-b737-445c79baaf06)<br>
**Preparation:** This is the foundational stage where we set the stage for incident response success. We create a well-defined incident response plan tailored to our organization's needs. We identify and designate incident response team members with specific roles and responsibilities. We establish communication protocols, both within the team and with external parties like law enforcement or vendors. Additionally, we ensure we have the right tools, technologies, and resources at our disposal, such as forensic software and incident tracking systems.<br>

**Detection and Analysis:** In this phase, we're like digital detectives. We constantly monitor our networks and systems for any unusual or suspicious activities. We use intrusion detection systems, log analysis tools, and security information and event management (SIEM) systems to spot signs of potential incidents. When something looks amiss, we investigate further to understand the nature and scope of the incident. We gather evidence, analyze malware, and determine how the attacker gained access.<br>

**Containment, Eradication, and Recovery:** Once we confirm an incident, our immediate goal is to stop it from spreading and causing more harm. We isolate compromised systems from the network, shut down unauthorized access points, and lock down affected accounts. Simultaneously, we work to eradicate the root cause by removing malware, closing vulnerabilities, and patching systems. Our ultimate aim is to get back to business as usual, so we focus on recovery—restoring data, services, and systems to their pre-incident state.<br>

**Post-Incident Activity and Lessons Learned:** After the dust settles, we don't just move on. We conduct a thorough post-incident analysis. We assess our incident response performance, identifying what we did well and where we can improve. We document lessons learned, update our incident response plan and procedures based on these insights, and ensure that any legal or compliance requirements are met. This phase is all about continuous improvement, so we're better prepared for the next incident.<br>

## Incident 1: Brute Force Success (Windows)
**Step 2: Detection and Analysis**

![Screenshot 2023-09-05 193524](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/11e3dfa1-8dd5-4a05-9f91-75be9b8b511f)

- Incident was triggered on 05/09/2023 3:39 pm
- Affected Machine: windows-vm
- Attacker IP: 188.128.73.66 (Yekaterinburg, Russia)
- Attacker entity failed 5 previous brute attempts earlier in the day before the final successful attempt.<br>

![Screenshot 2023-09-05 195042](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/45aedba5-fcd5-40ba-ab29-374145a1c7c8)<br>

 
- Potentially compromised system ‘windows-vm’ involved in several other incidents/alerts. Possible overexposure to the public internet
- Inspected actions from 188.128.73.66, there were 12 “successes” from the MOVS/Anonymous account but upon further investigation it was found that the alert raised was a false positive created by a service account.<br>

![Screenshot 2023-09-05 201937](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/50661698-24f2-46c3-8a6f-5dc2c2e9c2b3)<br>

  
- After the “successes” the attacker continued brute force attempts at the system, which suggests that they had not gained any significant access to user/admin accounts on the system, such as the “labuser”.<br>

![Screenshot 2023-09-05 201759](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/9d4a604a-4d54-4259-9b4a-b3d92b02c84e)<br>


- Although a false positive was generated, we still have a medium-level issue to resolve since this type of traffic should not be reaching the windows-vm in the first place.
- Closing out the incident as a false positive but will start the process for hardening network security groups.<br>


![Screenshot 2023-09-05 203815](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/6524ed42-0e51-4602-963d-a4ff4dda4984)


**Step 3: Containment, Eradication, and Recovery**

- I locked down the network security group assigned to the windows-vm and subnet by only allowing traffic from known IP Addresses that I will be accessing the VNet from.
- I enabled MFA for all user accounts on the virtual machine and in Azure AD.
  
## Incident 2: Possible Privilege Escalation (Azure Active Directory)
**Step 2: Detection and Analysis**

![Screenshot 2023-09-05 222944](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/90ceca30-453b-49c5-95d7-19b2af5e2994)<br>

- Incident was triggered on 05/09/2023 10:24 pm
- Same user viewed critical credentials several times:

Name - Lachlan Simpson

User Principal Name - lachie.simpson_hotmail.com#EXT#@lachiesimpsonhotmail.onmicrosoft.com<br>

![Screenshot 2023-09-05 224003](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/dd5a97c8-61fc-4e18-93d5-67486c2249a4)<br>

- Not only did this user view the critical credentials multiple times, they also are involved in several other incidents, including excessive password resets and global admin role assignment.
- After calling the above user, they confirmed that they were just doing their normal duties, corroborated this with their manager. Closing out for a benign positive.<br>

![Screenshot 2023-09-05 224048](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/7718dac8-4358-4719-a8ce-32928c09b8d4)


## Incident 3: Brute Force Success (Linux)
**Step 2: Detection and Analysis**

![Screenshot 2023-09-06 105344](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/1177d686-d8a3-4fea-8360-316d179a2a4c)<br>


- Incident was triggered on 06/09/2023 10:14 am
- Attacker at IP Address 1.157.141.118 involved in several other incidents.
- Several alerts have triggered and incidents have been automatically created based on action from this IP address.<br>

  ![Screenshot 2023-09-06 105550](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/e00cd2e8-ce3a-450e-aba5-c8ce5a052c44)<br>

- These incidents include several failed brute force attempts on Linux Syslog, a number of failed Azure AD brute force attempts, and one successful Azure AD brute force login.
- The event was confirmed to be a true positive through querying the attacker IP address in Syslog logs.<br>

 ![Screenshot 2023-09-06 110649](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/1b45d7c3-03b0-491a-b4c1-04a8ab2a29ed)



**Step 3: Containment, Eradication, and Recovery**

Initial response actions:

- The origin of the attacks was determined to be 1.157.141.118, and it was confirmed that this IP has been involved in other brute force attacks on Azure AD.
- This event occurred due to network security groups not being properly configured and is currently wide open to the public internet.
- The affected machine was immediately de-allocated to isolate it from other systems on the virtual private cloud.

This event was remediated by:

- Resetting the password for the compromised user.
- Locking down the network security group assigned to the linux-vm and subnet by only allowing traffic from known IP Addresses that you will be accessing your VPC from.

Impact:

- Account was local to the Linux machine, non-admin, essentially low impact. However, the attacker was involved in many other incidents. These will be remediated through NSG hardening. After the machine had been successfully isolated, the password reset, and it was confirmed that there was no successful lateral movement. The ticket was closed out as a true positive.<br>

![Screenshot 2023-09-06 112235](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/7e568a63-2d51-444f-a578-c0ad906cc8f2)

  
## Incident 4: Malware Detected
**Step 2: Detection and Analysis**

![Screenshot 2023-09-06 124254](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/3234054b-fb66-4117-9491-2e8f0e52625b)<br>


- Incident was triggered on 06/09/2023 9:34 am
- The host machine affected was windows-vm
- Several other security alerts have been associated with this VM.<br>

![Screenshot 2023-09-06 124946](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/c73e65d9-d188-4a08-bf60-96e66b3a1524)<br>


- As far as malware goes, this alert was a false positive because it looks like the user was testing with EICAR files.
- Here is the KQL query we used:<br>

![Screenshot 2023-09-06 130223](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/da594683-7305-423c-865c-f257523eddeb)<br>

- Corroborated with the user and user manager to determine if this false positive checks out with them. They confirmed that they were testing the anti-malware software on the machine.
- Closed out the ticket as a false positive.<br>

![Screenshot 2023-09-06 130915](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/6bd9da32-3906-4532-8991-a3e3cccdfb58)
