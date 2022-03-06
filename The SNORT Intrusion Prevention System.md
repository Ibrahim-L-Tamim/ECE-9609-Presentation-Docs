# The SNORT  Intrusion Prevention System
Saturday,  March 5, 2022 (By Ibrahim Tamim) 

This document covers a general overview of Intrusion Prevention Systems (IPSs). Specifaclly, it will covers SNORT, which is the world's leading open-source IPS. You can access a PDF  of the slides discussing this topic [here](http://youtube.com/). 

The document first covers what network intrusion are and examples of such attacks to clearly highlight the problem and the need for counter measures such as IPSs. Then, it will discuss IPSs in general and the differences between IPSs, Intrusion Detection Systems (IDSs), and Firewalls. Finally, it will discuss SNORT and go through example Denial of Service (DoS) attacks and how to defend against them using SNORT.
## Introduction 


**Network Intrusions:** are incidents when an attacker gains unauthorized access to a private/enterprise network or a specific machine within that network. When a intrusion doesn’t change or alter the network’s structure or information, it’s a passive intrusion. Passive intrusions are dangerous as the intruder can gather information and carry reconnaissance to prepare for a more sophisticated attack on the network. On the other hand, when an intrusion alters and changes any of the network’s resources, it’s an active intrusion. Active intrusions can be detected more easily than passive ones. However, they’re usually detected after the damage has already been done.

An attacker may penetrate the network by having physical access to a restirred machine, or a network component. Or they can attack the network remotely by gaining access through attacking the network’s protection function such as firewalls and Intrusion detection and preventions systems.

An intruder can gain access for a targeted one-time attack (e.g., injecting malware) or they can “live” in the network for extend periods of time (carrying different attack and staling information).

*for more information about INetwork Intrusions you can visit [this](https://www.sciencedirect.com/topics/computer-science/network-intrusion) link.*


# Network Intrusion Attacks
There are several attack types intruders can use to gain unauthorized access to the network, below are examples of the most common attacks. 

- **Multi-Routing:** This attacks depends on asymmetric routing. A network must have asymmetric routing enabled for an attacker to attack the network using many different malicious packets through different routes which hinders some of the firewall’s defenses.
- **Buffer Overwriting/Overflowing:** If malicious code can carry a buffer Overwriting/Overflowing attack on machines that are present in the target network, they can inject code that allows for malicious packets to penetrate the network by adding bypass rules to the network’s defenses (Firewalls, IDSs, IPSs).
- **Covert CGI Scripts:** One of the most common entry points for network attackers is the Common Gateway Interface (CGI). Attackers use the CGI to access system files. This is possible as the CGI is used to allow servers to pass requests by the users to relevant applications and vice versa. By accessing system files and directories, attackers inject malicious scripts that can facilitate their penetration of the network. However, as this attack was really common, today, much fewer devices provide CGI..
- **Traffic Flooding:** By overwhelming the network with massive amounts of traffic, the network’s defenses become unable to process all the traffic which either crashes the defense services creating errors that malicious attacks can hide behind, or malicious packets will slip under the massive traffic being sent to the network. 
- **Worms:** The common standalone executable viruses are considered one for the deadliest attacks on any machine. This is because the attacker can craft the virus with very limited constraints leading to it becoming extremely powerful. However, for a virus to infect a machine, legitimate users have to unwillingly execute or run those infected files. This is commonly done be sending malicious email attachments or messages that trick the legitimate users. There are many types of worms, works that steal massive amounts of information, worms that carry ransomware attacks, and in our use case worms that alter system files and rules to allow for network penetration. 

*for more information about Intrusion Attacks you can visit [this](https://www.cynet.com/network-attacks/network-attacks-and-network-security-threats/) link.*


## Intrusion Prevention System (IPS)
To counter netwrok intrusions by detecting and taking actions agaisnt malicuous requests and access attemps netwrok implement a IPS secuiryt function. 
IPSs are security tools that are tasked with continuously monitoring the network for any penetration attempts or malicious request/activities. IPSs also act against any detected intrusion attempt. These actions include reporting, blocking or dropping the detected requests. IPSs can be hardware-based network functions or software-based network functions. 


- **Signature-Based:** Well-known threats have clearly identified signatures. This methods tries to detect these signatures to identify the threat. A major limitation for such an approachis new threats/attacks (unknown signatures). 

- **Anomaly-Based:** A baseline standard of the subject network must first be defined. The method will identify any suspicious or anomalous behaviors in the network’s traffic. A drawback for such an approach is that it produces false positives. 

- **Policy-Based:** Administrators and network engineers have to set-up and define clear network policies that the IPS will execute while monitoring a specific network.


## The Importance of IPSs by VMWARE
"There are several reasons why an IPS is a key part of any enterprise security system. A modern network has many access points and deals with a high volume of traffic, making manual monitoring and response an unrealistic option. (This is particularly true when it comes to cloud security, where a highly connected environment can mean an expanded attack surface and thus greater vulnerability to threats.) In addition, the threats that enterprise security systems face are growing ever more numerous and sophisticated. The automated capabilities of an IPS are vital in this situation, allowing an enterprise to respond to threats quickly without placing a strain on IT teams. As part of an enterprise’s security infrastructure, an IPS is a crucial way to help prevent some of the most serious and sophisticated attacks." \[VMWARE, 2022]

## SNORT
SNORT is the leading and most-known IPS in the entire networking world. SNORT’s massive policy/rule –based database helps protects network traffic by deploying SNORT in an inline manner. As an IPS SNORT detects, alerts, and defends against network penetration attacks. 

SNORT’s three primary functions are: 
- Packet sniffer: Scan and read all incoming network traffic and present them through a selected display console or interface. 
- Packet logger: Save and log all incoming packets and save them in a specified logging directory.
- Full-blown network IPS: Deploy SNORT as an IPS to detect intrusion based on user-specified rules and polices and then take the necessary actions to handle the malicious packets. 

## SNORT’s Benefits
- **Additional Security:** As anomaly detection is one of SNORT’s major advantages, it can work closely with other security functions within the network to provide a higher level of security at the application level. (SNORT has access to packet contents) 

- **Increased Efficiency:** SNORT is not the only security function present for protection. So, by detecting, and dropping malicious network traffic, SNORT reduces the load on other deeper security functions. This dramatically increases the efficiency of the network’s defenses. 
  
- **Time and cost efficiency:** SNORT is automated. This means reduced cost of management and operation. And a much more time efficient protection as minimal human input is required. 


## How to install SNORT? 
The source to install SNORT is as follows: 

```console
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
                      
wget https://www.snort.org/downloads/snort/snort-2.9.19.tar.gz
tar xvzf daq-2.0.7.tar.gz
                      
cd daq-2.0.7
./configure && make && sudo make install
tar xvzf snort-2.9.19.tar.gz
                      
cd snort-2.9.19
./configure --enable-sourcefire && make && sudo make install
```
## Example Attacks That SNORT Protects Against 

|Attack                        |Description                   |
|-------------------------------|-----------------------------|
|DDoS Attacks	          |An attempt to make a server, service, or network unavailable by overwhelming it with a flood of traffic from multiple, distributed computing systems.|
|Smurf Attack            |A type of DoS attack in which a system is flooded by a large number of Internet Control Message Protocol (ICMP) packets, rendering the victim’s network unresponsive.|
|Ping of Death	|A DoS attack in which an attacker attempts to crash a system by sending malformed or oversized packets, using a ping command.|

You can access the full table and more inforamtion about these attacks [here](https://www.exabeam.com/ueba/ips-security-how-active-security-saves-time-and-stop-attacks-in-their-tracks/).

## Detailed Examples of SNORT Rules to defend agaisnt DoS Attacks
###  **1.** Land Attacks
- **What is the attack?** It’s an attack that results in the subject machine requesting to connect to itself continuously. This is achieved when the attacker first spoofs then resends a TCP SYN packet to the machine with all sources and destinations set as those of the subject machine. 
- **SNORT Rule for Land Attacks** 
```console
alert tcp any any -> any any (msg: "Land attack detected"; flags:S; sameip; sid: 5000000; rev:1;) 
```

Below are the descriptions for different SNORT rule components for this examples and all the following ones. 

**"msg":** display a message corresponding to the detected alert. 
**"flags":** flags that this detected attack will activate. "S" flag is the TCP SYN flag. 
**"sameip":** to check if the source IP is the same as the destination IP. 
**"sid":** the unique id for the SNORT rule.
**"rev":** to identify the revisions of the SNORT rule.


###  **2.** SYN Flood 
- **What is the attack?** An attacker targets a host by flooding it with TCP SYN packets. However, these packet requests are sent from spoofed IP address. This means that the server will never be able to receive an ACK message back from these requests leading to a flood.  
- **SNORT Rule for Land Attacks** 
```console
alert tcp any any -> 192.168.1.3 any (msg:"TCP SYN flood attack detected"; flags:S; threshold: type threshold, track by_dst, count 20 , seconds 60; sid: 5000001; rev:1;)
 
```

**"threshold ":** number detections that must occur per minute for an event to be logged.
**"track by_dst":** the destination IP to track by. 
**"count":** the count of the number of events. 
**”seconds”:** the time frame for counting the number of events.


*You can read the paper below for more attacks and SNORT defense rules.*

Trabelsi, Zouheir & Alketbi, Latifa. (2015). Using Network Packet Generators and Snort Rules for Teaching Denial of Service Attacks. 10.13140/RG.2.1.1196.4646.  

## Additional Resources and Research Papers
- [IPS Security: How Active Security Saves Time and Stops Attacks in their Tracks](https://www.exabeam.com/ueba/ips-security-how-active-security-saves-time-and-stop-attacks-in-their-tracks/)

- [Snort Alerts](https://docs.netgate.com/pfsense/en/latest/packages/snort/alerts.html)

- [IDS vs. IPS: Definitions, Comparisons & Why You Need Both](https://www.okta.com/identity-101/ids-vs-ips/)

- [Understanding and Configuring Snort Rules](https://www.rapid7.com/blog/post/2016/12/09/understanding-and-configuring-snort-rules/#:~:text=Snort%20rules%20must%20be%20contained,it%20is%20contained%20in%20snort.)

- A. H. Al-Hamami and G. M. W. Al-Saadoon, "Development of a network-based: Intrusion Prevention System using a Data Mining approach," 2013 Science and Information Conference, 2013, pp. 641-644.

- P. R. Chandre, P. N. Mahalle and G. R. Shinde, "Machine Learning Based Novel Approach for Intrusion Detection and Prevention System: A Tool Based Verification," 2018 IEEE Global Conference on Wireless Computing and Networking (GCWCN), 2018, pp. 135-140, doi: 10.1109/GCWCN.2018.8668618.

- S. Zhou, "Evaluation of the Runtime Intrusion Prevention of ARM-Based Systems in Wireless Networks," 2020 IEEE 3rd International Conference on Computer and Communication Engineering Technology (CCET), 2020, pp. 289-293, doi: 10.1109/CCET50901.2020.9213116.

- R. Z. A. da Mata, F. L. de Caldas Filho, F. L. L. Mendonca, A. A. Y. R. Fares and R. T. de Sousa, "Hybrid Architecture for Intrusion Prevention and Detection in IoT Networks," 2021 Workshop on Communication Networks and Power Systems (WCNPS), 2021, pp. 1-7, doi: 10.1109/WCNPS53648.2021.9626246.

- R. Abhijith and B. J. Santhosh Kumar, "First Level Security System for Intrusion Detection and Prevention in LAN," 2021 2nd International Conference for Emerging Technology (INCET), 2021, pp. 1-5, doi: 10.1109/INCET51464.2021.9456259.

- M. Nadeem, A. Arshad, S. Riaz, S. S. Band and A. Mosavi, "Intercept the Cloud Network From Brute Force and DDoS Attacks via Intrusion Detection and Prevention System," in IEEE Access, vol. 9, pp. 152300-152309, 2021, doi: 10.1109/ACCESS.2021.3126535.

- S. Li, H. Liu, W. Lv and C. Liu, "Campus network intrusion prevention and detection application research," 2021 IEEE 4th Advanced Information Management, Communicates, Electronic and Automation Control Conference (IMCEC), 2021, pp. 1216-1220, doi: 10.1109/IMCEC51613.2021.9482161.

- P. Freitas De Araujo-Filho, A. J. Pinheiro, G. Kaddoum, D. R. Campelo and F. L. Soares, "An Efficient Intrusion Prevention System for CAN: Hindering Cyber-Attacks With a Low-Cost Platform," in IEEE Access, vol. 9, pp. 166855-166869, 2021, doi: 10.1109/ACCESS.2021.3136147.

- W. Seo and W. Pak, "Real-Time Network Intrusion Prevention System Based on Hybrid Machine Learning," in IEEE Access, vol. 9, pp. 46386-46397, 2021, doi: 10.1109/ACCESS.2021.3066620.













