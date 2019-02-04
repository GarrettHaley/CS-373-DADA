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
This weeks write up will focus on the lecture content regarding advanced forensics created by the Director of Threat Intelligence Malware Operations at McAfee Labs. Overall, I found the material to be more interesting than last week. I will go over some notes from the lecture, tools introduced for forensics, and this weeks challenge: Analyzing an image of a USB drive found on a DPRK Defector caught close to the boarder of North and South Korea.

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

This week has been an interesting look into forensics. I thought the USB analysis challenge was really interesting and a good opportunity to try out different tools from the lectures. FTK imager, FileInsight, and PhotoRec were all useful tools for my analysis. The primary focus of the lectures involved the incident response process, investigation process, and memory dumps. The lectures were particularly intersting coming from someone who has had extensive experience in the field.

## Week 3 Write Up

This weeks write up will focus on the lecture content regarding malware defense. Specifically, the material covered places to detect, block/remove a threat, adversarial attack vectors, and attack graph/flow information. The end of the write up will contain the YARA lab as well as the blog asked for from this week's lecturer (scroll to the bottom of this weeks write up to see this).

#### Key Malware Activities

- First contact (mediums adversaries use to reach their victims): Email, instant messaging, malvertising, poisoned search results, watering hole, physical access.
- Local execution: Established through social engineering, explotation or abusing features.
- Establishing Presence: Blending/hiding in plain sight by appearing to be legitimate (OS-like file names, signed, etc).
- Malicious Activity (information is harvested):
1. Enumerating docs, passwords, processes, etc.
2. Applying a hook via browser, a keylogger, etc.
3. Getting log information.

#### Detect, Block, or Undo Attacks at Each Stage?

- First Contact: 
1. Spam: Anti-spam.
2. Network: Firewall.
3. Network IPS, Web: IP, Domain, and URL reputation.
4. Physical access: Disk encryption.
- Local Execution: 
1. Spam: Client-side content filtering.
2. Network: Network IPS.
3. Web: Content filtering/scanning.
4. Host: Host IPS, Anti-virus, Whitelisting.
- Establish Presence: 
1. Host: Anti-virus.
2. Whitelisting, HIPS.
3. Network: Firewall.
4. Network IPS, Web: IP, Domain, & URL reputation.
- Malicious Activity: 
1. Host: Anti-virus.
2. Network: NIPS, Firewall.
3. Web: IP, Domain, URL rep & content filtering, Data Loss Prevention.

#### Advantages and Disadvantages of Anti-malware Automation

Advantages: Scalable, consistent, and lower performance concern.  
  
Disadvantages: Potential context issue, prone to invasion, and an increase in denial of services attacks and probing.

#### YARA

YARA is the pattern matching Swiss knife for malware researchers. Using YARA, strings can be followed by nocase (case insensitive), wide (strips zeroes in unicode strings), wide ascii (searches both wide and ascii strings), fullword (full delimited strings), Byte patterns (Hexadecimal strings), Accepts “?” and “??” wildcards, or Jumps to denote a number of wildcards.

Inside YARA there is a rule browser (list of previously saved rules), an IDE (where you write code), malware broswer (browse samples to run on), an inspector (shares malware, name, path, size, md5, and sha1 information), and the rules generator (this will find all common strings among samples, but the rules are not very good).

#### YARA Lab

Following the examples given in lecture, I ran the YARA tool on files in 
- C:\Users\Admin\Desktop\malware\Malware Defense\Class1\Sample Group 1\
- C:\Users\Admin\Desktop\malware\Malware Defense\Class1\Sample Group 2\ 
- C:\Users\Admin\Desktop\malware\Malware Defense\Class1\Sample Group 3\ 

From C:\Users\Admin\Desktop\malware\Malware Defense\Class1\Sample Group 1\ I found "AikaQ" and "Jenna Jam" matched to all files in the /sytro directory. This can be seen below:

<img src="week3_yara-0.PNG" alt="hi1" class="inline"/>
<img src="week3_yara-1.PNG" alt="hi1" class="inline"/>

Following the same process from C:\Users\Admin\Desktop\malware\Malware Defense\Class1\Sample Group 1\, the files in C:\Users\Admin\Desktop\malware\Malware Defense\Class1\Sample Group 2\ matched with "DownloaderActiveX" and the files in C:\Users\Admin\Desktop\malware\Malware Defense\Class1\Sample Group 3\  matched with “TuguuAdw”.

#### Cuckoo 
Cuckoo is an automated malware analysis tool that allows you to understand what a given file does when executed inside an isolated environment. It can bypass sleep bombs by intelligently skipping sleeps, emulate user interaction by moving mouse and pushing buttons, randomize the system clock with each run, and use a randomly named cuckoomon.dll.

An analysis using Cuckoo would look like an isolated vpn with clean environments to run a sample, and a Cuckoo host which is responsable for guest and analysis management of the environments running the samples (the internet/sinkhole). More specifically, it traces win32 API calls performed by all processes spawned by the malware, tracks files being created, deleted and downloaded by the malware during its execution, gets memory dumps of the malware processes, provides network traffic trace in PCAP format, contains screenshots of Windows desktop taken during the execution of the malware, and full memory dumps of the infected machines.

#### Malware Defense BLOG - Chinese Trojan can Steal Passwords and Other Sensitive Information from your Computer -
Author: Garrett Haley  
Saturday, January 26, 2019 (PST)  
MD5 Malware Hash: 068D5B62254DC582F3697847C16710B7  
MD5 YARA Hash:    144de687e53db1eed2be97d749358cdc

While there are an increasing number of malware authors who are using encryption and obfuscation to modify the static contents of malware to thwart security researchers from static-based clustering, there are many instances of malware which are not making the necessary attempts to hide its behavior. This allows researchers to devise systems of identifying such malware. If such malware is not identified, your sensitive personal information may be at risk from malware like the chinese trojan discussed in this article.


#### Origin of Identification

While performing a simple strings analysis on the potential malware, key terms such as "QQLogin.exe","GetTuPian.asp", "DNF.exe", “RegSetValue”, "Keyboard" and many more were discovered. When cross referenced online, there is a strong indication the file may be a trojan that steals passwords and other sensitive information. The trojan can send the information to a remote machine. The file is run-time compressed using UPX. 

<img src="week3_exe_1.PNG" alt="hi51" class="inline"/>

To verify that we have indeed identified the malware, more evidence is needed. More strings such as "del%x.bat" and "%x" further incriminate the file as "del%x.bat" is most likely references deleting a batch file which has some sort of name randomization happening which would make the software more difficult for anti-malware programs to detect. Further, during program execution, there is an attempt to add a registry key: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run -> c:\qusla.exe. This program performs a lot of registry activities related to the keyboard (RegEnumKey for HKLM\System\CurrentControlSet\Control\Keyboard Layouts, Registry activity for HKCU\Control Panel\Input Method\Hot Keys). This indicates there may be some sort of keylogger involved.

#### How to tell if you are Infected

<img src="week3_lab_yara.PNG" alt="hi51" class="inline"/>

Based on the activities identified during the original malware identification, I have created a YARA file which can can be seen above to test a file for potential infection. The activities targeted with the YARA file are the strange address referenced containing "GetTuPian", the executables "QQLogin.exe", "DNF.exe", register alterations "RegSetValue" and "Keyboard".

## Week 4 Write Up

This week's write up will focus on the lecture content created by Brad Anton. This consisted of discussing real life hacking and trends, exploits, and WinDBB. Overall, this was my favorite week so far. I thought Brad was pretty entertaining and knowledgeable. I will say it may have been difficult to follow some of what he said if I hadn't taken CS 519 (Cyber Attacks and Defense) last quarter. I thought he did a good job reviewing some of the basics of what I learned from that class as well as add his own material.

#### Manipulating Software

This week began with Brad speaking generally about what software manipulation is. Essentially it boils down to finding bugs which alter the behavior of programs and take advantage of a misconfiguration or poor programming practices. The example he gave the class was a simple road example. Imagine you are in a program driving a vehicle and their is a choice to turn left or right with an input prompt. What are your choices? Well, the programmer only gave you two choices: left or right. But what if you try going forwards instead? This may lead to a potential path the programmer had not envisioned. On this path, you may find some adversarial advantages.

Brad went on to talk a little bit about how things have changed in his lifetime. In the internets infancy stages, hacking usually took on less harmful dimensions than what we say today. Website defacement, denial of services attacks were the norm. As we have become more  reliant on the internet and our connected devices, a much higher level of threat sophistication and malice has increased. Brad briefly discussed cyber armies and bug bounty programs to further show how much money and energy is now spent in the cyber security domain.

#### Defintions:
- Memory Corruption: Accessing memory in an invalid way which results in an undefined behavior.
- Exploitation: Taking advantage of a vulnerability. This consists of a vulnerability trigger and payload.
- Vulnerability Trigger: Invokes the software bug to obtain control of the program.
- Payload: Action to be performed when control is obtained. Typtically contains shell code.
- Shell Code: Usually assembly code to execute a shell (e.g. /bin/sh).

#### WinDBG Introductions

WinDBG was introduced during the first lecture as well as a walkthrough challenge with posted solutions in which we had to attach WinDBG to a running internet explorer process. We were introduced to the following commands in WinDBG:
- Viewing Memory: dd, da, du
- Breakpoints: bp <addr>
- Clear all: bc *
- Stepping: t, p
- Disassembly: View->Disass.
- Conversion: .formats
- Math: ?1+1
- Modules: lm
Extensions:
- Process (inc heap): !peb
- Thread (inc stack): !teb
- What Addr?: !address  
 
 #### Flaw Classes and Vulnerabilities Examples
 
 Configuration flaw: A weak password.  
 Logic flaw: Authorization issues.  
 Storage: Inadequate Encryption.  
 Input Validation: Memory corruption, injection.  
 
 #### Getting Code Execution (Stack)
 Step 1: Crash Triage. This consists of discovering what us (the attacker) controls, e.g what registers container attacker-controlled data, what registers point to attacker-controlled data, is the data on the stack or heap, is the controlled data critical, etc.  
 Step 2: Determine the return address offset, e.g how many bytes to the return address.  
 Step 3: Position shellcode: provide NOP sleds (0x90's) to code.  
 Step 4: Find the address of the shellcode: Use this to overwrite the return address to return to your desired shell code.  
 
 #### The heap
 
 The second lecture spent time on attempting to perform a heap overflow on an object which control had been overturned by an adversary. A heap overflow is a type of buffer overflow which occures in the heap data area and is different than the stack overflows discussed in the previous lecture. In this structure, memory is dynamically allocated by an application during runtime and contains program data. By controlling an object in the program data it is possible to corrupt the data in a specific way which causes internal structures, e.g, a program function pointer. Brad went over various tools like "Page Heap" which is designed for debugging the heap which can be enabled via gflags to free an object and the !heap WinDbg extension which helps to discover heap information (and more).
  
  #### Conclusions
  
  Overall, I enjoyed the material this week. The heap and stack overflow attacks were mostly review for me from CS 519. The tools and some of the vocabulary (ex: crash triage) were new to me. Last summer I had the opportunity to do some penetration testing during my last internship. I thought this information was pretty valuable and related to what I will be doing directly after graduation.
 









