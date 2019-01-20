## Week 1 Write Up
This week's write up will focus on the lecture content created by the Director of Threat Intelligence Malware Operations at McAfee Labs. Overall, I found the material to be pretty engaging and interesting. I will go over a little bit about what I learned about malware, why it exists, naming conventions, role of malware researchers, some security definitions I learned, and review aspects of Advanced Persistent Threats (APT's).

#### Why Does Malware Exist?

The primary reason for malware existing spoken upon in lecture generally falls under political/economic gain, defacement/destruction, and reconnaissance/spying. The malware examples spoken about during lecture (sony attack, middle east attacks, etc.) all have adversary profiles with one or more of the primary motivations described above. 

#### Strategy used by Attackers

The lecturer provides one model for attack stategy which involves the following 7 steps:
1.  Reconnaissanc: Discreetly discovering information regarding the target (can be passive or active). One example of this was gathering metadata companies accidentally attach to PDF's which provide valuable information to adversaries.
2. Weaponization: Vector of attack being determined.
3. Delivery: Attack being delivered via emails, USB sticks, trojans, etc.
4. Exploitation: Execuation of the exploit.
5. Installation: Installing the payload.
6. Command and Control: Enables the adversary to do what they need to achieve their task (i.e destroy a system, retrieve information, etc).
7. Actions and Objectives: Execute tasks and objectives.

#### Early Careers in Developing Anti-malware

Careers used to be hard to combe by in computer antivirus research. Commercial anti-virus did not come out to the market until the early 1990's. Up until this point, primary jobs market was to work for the computer antivirus research organization formed in 1990. The market now has over 10 billion invested in the endpoint security market with over a million positions unfilled worldwide.

#### What are the Roles of a Malware Researcher?

The primary role of an malware researcher is to follow best practices, etiquette and safe computing. Futher the researcher should be able to understand a describe the threat, create countermeasures, and approach the design from an anti-attacker perspective. 

#### Basic Malware/Security Definitions:

1. Sample - Piece of malware.
2. Goat - What you ar giving the malware (i.e virtual machines, etc).
3. Bootkits - Master boot record infection. Hidden encrypted disk partition where malware and rootkits are executed. These were popular in the 1980's (malware popularity type comes in waves).
4. Trojan horse - Masquerades as useful software but once installed, often create a backdoor to your computer that gives malicious users access to your system, possible allowing confidential or personal information to be compromised.
5. Spyware - Software that collect personal information without the user’s knowledge or consent for advertorial or fraudulent purposes. 
6. RATS - Remote Aceess Tools System Software.
7. CVE - The Common Vulnerabilities and Exposures (CVE) system provides a reference-method for publicly known information-security vulnerabilities and exposures. 
8. Ransomeware - Software which encrypts users files and will unencrypt them if a user is willing to pay for them.
9. Static Analysis - Performed without the benefit of dynamic execution environment. Pros: Discover what the author intended the code to do, even if that can not be observed in lab environment. Cons: Can be expensive; out of context and external dependencies can not be evaluated.
10. Potentially Unwanted Program (PUP, PUA, PUS) – Adware, spyware, tools.

#### Malware Naming Conventions:
The naming convention is as follows: 
Type:->Platform/->Family->.Varient->!Information
Example: Trojan:Win32/Reveton.T!Ink

This standard format allows for security professionals to used shared terminology that is useful in identifying the malware type, platform its built for, family, its varient, and additional info. Its worth also mentioning this standard is not always followed (but should be more in the future!).

#### Advanced Persistent Threats:

The term advanced persistent threat or APT was created in 2006 by US Air-force analysts. It describes three main aspects of attackers:
Advanced – The attacker is fluent with cyber intrusion methods and administrative techniques, and is capable of crafting custom exploits and related tools.
Persistent – The attacker has an objective (or mission in longer-term campaigns) and works to achieve their goals without detection.
Threat – The attacker is organized, receives instructions, is sufficiently funded to perform their (sometimes extended) operations, and is motivated.

##### Characteristics of an APT:

1. Actors: Terrorists/activists, governments, organized crime groups, competitors, malicious insiders/ex-employee.
2. Motives: Money, disgruntlement/revenge, ideology, or excitement.
3. Targets: Large corporations, governments, defense contractors ... anyone.
4. Goals:
 - Use stealth during intrusion to avoid detection.
 - Create backdoors to allow greater access, especially if other access points have been discovered and patched.
 - Initiating the primary mission: Stealing sensitive data, monitoring communications, disrupting operations, leaving undetected.
 
#### Conclusions

Overall, I found this week to have great content. I am taking this class because I am interested in topics like malware analyis. During the lab I had the opportunity to perform a short malware analysis using FakeNet, ProcMon, Process Explorer, Antispy, and Flypaper. Each of the tools above have different uses. FakeNet is network emulation software to deceive evil.exe to believe it is connected to the internet. ProcMon displays the active file system, thread activity, and registry. Process Explorer displays a view of running processes and allows for further exploration of process details. Antispy identifies the malware (in our case, evil.exe) and dives into files in a system. Flypaper is designed to bar the ending of threads, processes, or memory. In summary, I found the malware makes a copy of itself, creates a schedule for its copy to be run every 30 minutes, alters the hosts file, rummages through system files/directories, attempts to make itself persist in the system, and tries to download an executable from the web on to the infected system. From the information gathered, I believe the malwares identity to be profile RDN/Generic.bfr!0012B0384774 which can be found here: https://home.mcafee.com/virusinfo/virusprofile.aspx?key=2369875#none. I know that I did not find everything, but this was an excellent opportunity for me to fiddle around with some of the tools and try to wrap my head around what it actually means to perform a malware analysis. The lab can be seen on canvas.

## Week 2 Write Up
This weeks write up will focus on the lecture content regarding advanced forensics created by the Director of Threat Intelligence Malware Operations at McAfee Labs. Overall, I found the material to be more interesting than last week. I really thought the challenge at the end was really interesting. I will go over some notes from the lecture, tools introduced for forensics, and this weeks challenge: Analyzing an image of a USB drive found on a DPRK Defector caught close to the boarder of North and South Korea.

#### What is Forensic Computing?

According to lecture, "forensic computing is the process of identifying, preserving, analyzing and presenting digital evidence in a manner that is legally acceptable” (Rodney McKemmish 1999). Essentially its the processing of discovering data of probative value from information systems using live forensics, post-mortem based forensics, and network based forensics. The four essential principles to be followed while performing computer forensics are to minimize data loss, record everything, analyze the data, and then report the findings. A key take away from the lecturer was to remember that it is not the forensic analysts job to decide if someone is innocent or guilty. It is to simply unearth facts regarding the information systems to aid in the investigation.

#### Incident Response (IC)

The incident response process consists of incident response team preparation, incident detection, initial response, strategy formulation, the investigation (data collection/forensic analysis), and the reporting stage. This can lead to legal action, administrative actions, and remediation (recovering from the incident).


#### The Investigation

The investigation cycle includes creating a timeline analysis (according to the lecturer, this is primarily still done on pen and paper), media analysis, string or byte search, data recovery, and reporting analysis. Physically, the data acquisition consists of gathering memory (virtual/physical), drives or partitions, and network traffic (packet captures). Its important to remember a few things while performing an investigation.
1. You cannot interact with a live system without having some effect on it.
2. Powering down the suspect system can destroy critical evidence.
3. When collecting evidence you should proceed from the volatile to the less volatile.

#### Memory Dumps

The three primary methods to enumerate information in memory dumps are to look for printable strings, reconstruct internal data structures, and search for static signatures of kernel data structures.

Malware related Volatility plugins/tools:
- Malfind: Detects hidden and injected code.
- Csrpslist: Detects hidden processes with crss.exe handles & CsrRoot-Process links.
- Orphan threads: Detects hidden kernel threads.
- PSList: Shows processes based on linked lists.
- PSScan: Shows processes based on the headers found in the “memory pool”.
- ... A few more: svcscan, ldrmodules, impscan, apihooks, idt, gdt, callbacks, driverirp, psxview, ssdt_ex, ssdt_by_threads. 

#### Analyzing the Image of a USB Drive Found on a DPRK Defector (Challenge)

This week involved the challenge of analyzing an image of a USB drive found on a North Korean defector. The following was my process and results of the challenge.

After listening to both clues given, I began with recovering the password to unzip the zipped directory and reveal a .csv file. This consisted of opening “don’t tell mrs Il Ung.jpg” in FileInsight and performing a simple strings analysis.

<img src="Week2_strings.PNG" alt="hi" class="inline"/>

Using the password found above, I was able unzip and view a .csv file which contained the following targets:
1.  GS Caltex 
- IP: 123.143.8.44 (Target)
2.  S-Oil infra
- IP: 125.135.116.33 (Target)
- IP: 125.135.116.38 (Target)
- IP: 125.135.116.39 (Target)
- IP: 125.135.116.47 (Target)

Next, I changed the bin file to run.exe as there was a hint that this file was the malware. I used a few of the tools from last week to analyze the malware. The FakeNet showed connections were attempted to 43.130.141.XXX (multiple) and 172.21.40.161. ProcMon showed the malware attempting queries from register HKLM\System\CurrentControlSet\services\NetBT\Linkage\Export

After mounting the Image_USB_Mayflower.001, I was able to recover some files using PhotoRec. Here are some of the them:

<img src="week2_NK3.PNG" alt="hi1" class="inline"/>
<img src="week2_NK2.PNG" alt="hi2" class="inline"/>
<img src="week2_NK.PNG" alt="hi4" class="inline"/>

#### Conclusions

This week has been an interesting look into forensics. I thought the USB analysis challenge was really interesting and a good opportunity to try out different tools from the lectures. FTK imager, FilInsight, and PhotoRec were all useful tools for my analysis. The primary focus of the lectures revolved around the incident response process, investigation process, and memory dumps. The lectures were particularly intersting coming from someone who has had extensive experience in the field.
















