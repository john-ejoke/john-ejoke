
## Cybersecurity Lab: SYN Flood Simulation and Defense
#### Simulating and Mitigating Network Attacks | Infrastructure Engineering

Author: John Ejoke Oghenekewe
Role: Cybersecurity Analyst | SOC Engineer

---

## Live Walkthrough

[![ICMP Ping Flood Uncovered — Cyber Experiments with J](https://img.youtube.com/vi/1NAS-7z1NK8/maxresdefault.jpg)](https://youtu.be/1NAS-7z1NK8?si=Y-1VsR3d2UENPXYm)

---

## Overview

I built this lab to answer a question that kept coming up in my learning: what does a network attack actually look like when it is happening, and what does it take to stop it? Not in theory. In a real environment, with real tools, watching real traffic.

To answer that, I set up two virtual machines on VirtualBox, put Kali Linux on one side as the attacker and Ubuntu on the other as the defender, connected them on an isolated host-only network, and ran a SYN flood from one to the other. I watched it hit in Wireshark, tracked it in Snort, and then built the defensive layers to shut it down. This document walks through everything I did and what I found.

**Tools used:** VirtualBox, Kali Linux, Ubuntu, hping3, Wireshark, Snort, iptables

---

## Building the Lab Environment

The setup was intentionally simple so the focus could stay on the attack and defense, not the infrastructure. VirtualBox with a host-only adapter gave me two machines that could talk to each other without any outside network exposure. Kali Linux at `192.168.56.104` was the attacker. Ubuntu at `192.168.56.103` was the target.

On the Ubuntu machine I installed Wireshark for live packet capture and Snort as the intrusion detection and prevention engine. Before doing anything else I configured Snort's `snort.conf` file, setting the `HOME_NET` variable to `192.168.56.0/24` so Snort understood the boundaries of the network it was protecting. Then I wrote the custom rules in `local.rules` that would tell Snort exactly what to look for.

---

## Installing Snort and Writing the Rules

Installing Snort was straightforward with `sudo apt-get install snort`. The more interesting part was writing the rules. I started with an alert rule to detect any SYN packet hitting port 80. The logic was simple: before I try to block anything, I want to confirm I can see it.

```
alert tcp any any -> any 80 (msg:"SYN Packet Detected"; flags:S; sid:1000002;)
```

Once detection was confirmed I added a drop rule to move from passive observation to active prevention:

```
drop tcp any any -> any 80 (msg:"SYN Packet Blocked"; flags:S; sid:1000003;)
```

The full rule set is in the `rules/local.rules` file in this repository. Snort was launched in detection mode with:

```
sudo snort -A console -q -c /etc/snort/snort.conf -i enp0s3
```

The output below shows Snort fully initialised, the rules engine loaded, and packet processing underway.

![Snort running on Ubuntu with rules engine loaded and packet processing commenced](screenshots/01-snort-installation-and-testing.png)

---

## Testing the Setup

Before running the flood I wanted to confirm two things: that the machines could communicate, and that Snort was actually picking up traffic. I ran a basic ping from Kali to the Ubuntu target. Seven packets transmitted, seven received, zero packet loss. The network was clean.

On the Ubuntu side, Snort immediately started generating alerts. Every ping was logged, the source IP flagged, the port recorded. The right side of the screenshot below shows Snort's console output in real time while the ping ran on the left. The detection pipeline was working exactly as expected.

![Kali ping on the left, Snort live alerts firing on the right](screenshots/02-traffic-simulation-and-detection.png)

---

## Executing the SYN Flood

With everything confirmed, I launched the actual attack from the Kali machine using hping3:

```
sudo hping3 --flood -S -p 80 -d 200 -w 64 192.168.56.103
```

The `--flood` flag sends packets as fast as the machine can produce them without waiting for any reply. The `-S` flag sets the SYN flag in the TCP header, meaning every packet is initiating a connection that will never be completed. The target's connection table starts filling with half-open sessions that never close, which is the whole mechanism of a SYN flood.

The attack ran for just over 16 seconds. When I stopped it, the statistics were stark: 530,498 packets transmitted, 0 received, 100% packet loss on the round trip. The Ubuntu machine was never going to respond to any of them. That was the point.

![hping3 output showing 530,498 packets transmitted and 0 received in 16 seconds](screenshots/03-attack-execution-from-kali.png)

---

## What Wireshark Captured

Wireshark was running on Ubuntu throughout the attack with the filter `tcp.flags.syn == 1` to isolate the SYN traffic. In the early seconds the packets arrived in sequence, one per second roughly, each one a SYN from `192.168.56.104` to `192.168.56.103` on port 80.

![Early Wireshark capture showing sequential SYN packets with tcp.flags.syn filter applied](screenshots/04-wireshark-capture.png)

As the flood scaled up the capture told a different story. By packet 1096 and beyond, port numbers were being reused because the connection table had run out of fresh ones. SYN packets were still arriving continuously at approximately 32,806 per second but now mixed with TCP port reuse warnings as the system strained under the load. There were no ACK responses anywhere in the capture. The handshake was never completed. Not once.

![Wireshark at scale showing port number reuse and SYN flood continuing at packet 1096](screenshots/05-impact-of-syn-flood-attack.png)

---

## Applying the Defenses

Seeing the attack land in Wireshark and Snort made the mitigation work feel concrete rather than academic. I applied four layers of defense on the Ubuntu machine.

SYN cookies were the first measure, enabling the system to handle legitimate connection requests even while the flood was happening:

```
sudo sysctl -w net.ipv4.tcp_syncookies=1
```

Rate limiting via iptables capped how many SYN requests the system would process per second, keeping it functional under pressure:

```
sudo iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
```

A firewall rule blocked the attacking IP directly at the network level:

```
sudo iptables -A INPUT -s 192.168.56.104 -j DROP
```

And the Snort drop rule intercepted malicious SYN packets at the detection layer, logging every blocked packet with a timestamp and source so the activity remained fully visible even as it was being stopped.

Each layer addressed a different part of the problem. Together they gave the system a way to survive the flood, filter the traffic, and maintain visibility throughout.

---

## What I Learned

The thing that stayed with me most was how different the attack looks depending on which machine you are sitting at. On the Kali side it is one command and a number. On the Ubuntu side it is Wireshark filling faster than you can read it and Snort alerts scrolling without stopping. Understanding both perspectives is what makes the defensive work real. You cannot write a rule that matters if you have not watched the thing you are trying to catch.

---

*John Ejoke Oghenekewe | Cybersecurity Analyst | SOC Engineer*
*GitHub: [github.com/john-ejoke](https://github.com/john-ejoke)*
