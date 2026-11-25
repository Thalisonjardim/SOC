# Network Traffic Analysis — Home Network Baseline

**Case ID:** NTA-001 | **Date:** November 2026 | **Category:** Blue Team / SOC Level 1

## Executive summary

This educational case study examines a real packet capture from a personal network to establish a small traffic baseline and distinguish observable events from hypotheses. No attack was confirmed within the limited observation window. I collected traffic from my own network and used Wireshark to inspect protocol statistics, DNS responses, TCP connection establishment and local discovery traffic. This project documents my learning and evidence-validation workflow, including AI-assisted exploration.

## Capture overview

- Environment: personal network, macOS, interface en0.
- Format: PCAPNG.
- Duration: approximately 25.32 seconds.
- Total: 326 frames, 93,606 bytes.

| Protocol | Frames |
|---|---:|
| TCP | 206 |
| UDP | 89 |
| ARP | 24 |
| ICMPv6 | 7 |

The network layer includes 240 IPv6 frames and 62 IPv4 frames; the remaining 24 are ARP. Wireshark's unfiltered protocol hierarchy identifies 22 QUIC, 65 TLS, 27 DNS and 7 mDNS frames. Counts across protocol layers overlap.

## Skills demonstrated

- Packet capture and protocol inspection in Wireshark.
- DNS request/response correlation and interpretation of A records, TTL and response time.
- TCP handshake and flag interpretation, including ECN and basic troubleshooting.
- Evidence-based SOC triage: distinguishing observed behavior from unconfirmed hypotheses.
- Privacy-aware technical documentation and responsible AI-assisted analysis.

## Methodology

1. Inspect Statistics > Protocol Hierarchy, Endpoints and Conversations.
2. Isolate protocols with display filters.
3. Correlate requests and responses using frame numbers, transaction IDs and transport ports.
4. Separate observations, hypotheses and follow-up actions.

## Evidence and findings

### 1. ARP and local discovery

Frames 42 and 43 show an ARP request and reply. Host A asked for the MAC address associated with Host B's IPv4 address; Host B replied. Host A also queried multiple other local addresses.

Filter: `arp` or `frame.number == 42 || frame.number == 43`.

Assessment: compatible with local device discovery. Repeated ARP requests alone do not prove malicious scanning or ARP spoofing. Identify the originating device before escalation.

### 2. DNS resolution

Frames 88, 89 and 90 contain HTTPS (type 65), AAAA and A queries for chatgpt.com. Frames 103, 99 and 100 respectively contain their responses.

| Frame 100 field | Value |
|---|---|
| Transaction ID | 0x84a1 |
| Query type | A |
| Answer count | 2 |
| TTL | 217 seconds |
| IPv4 answer 1 | 104.18.32.47 |
| IPv4 answer 2 | 172.64.155.209 |
| Request frame | 90 |
| Response time | 5.436 ms |

DNS transport used IPv6, which can resolve IPv4 records.

Filter: `dns.qry.name == "chatgpt.com" && dns.flags.response == 1 && dns.qry.type == 1`.

To investigate subsequent traffic: `ip.addr == 104.18.32.47 || ip.addr == 172.64.155.209`. Also inspect AAAA answers and IPv6 conversations.

Assessment: DNS resolution alone does not establish that a user visited a website. Background applications and shared hosting complicate attribution.

### 3. TCP connection establishment

Frames 1, 3 and 4 contain SYN, SYN-ACK and ACK between client port 63042 and remote port 443. ECN negotiation flags are present. The handshake completed at 0.084723 s. Frame 6 shows a TLS Client Hello with an iCloud service hostname; this stream is not evidence of a ChatGPT connection.

Frames 10 and 11 are flagged as previous segment not captured and out-of-order, respectively. These flags alone do not establish malicious activity.

Filters: `tcp.port == 63042`, `tls.handshake.extensions_server_name`.

### 4. UDP and service discovery

54 UDP frames involve port 443; the protocol hierarchy confirms 22 QUIC frames. Seven frames involve port 5353. Frames 143 and 144 contain mDNS service discovery queries for SMB, RFB, AFP and ADISK.

Filters: `udp.port == 443`, `quic`, `udp.port == 5353`.

Assessment: discovery does not establish that services are enabled or vulnerable. UDP/443 alone does not prove QUIC or HTTP/3.

### 5. ICMPv6 operational event

Frame 104 contains ICMPv6 Type 1, Code 4 (Destination Unreachable / Port Unreachable), following a DNS response. A closed UDP socket is a plausible explanation, not a confirmed root cause.

Filter: `icmpv6.type == 1 && icmpv6.code == 4`.

## Manual evidence validation

Six Wireshark screenshots were collected: unfiltered protocol hierarchy, DNS response, TCP handshake, ARP, mDNS and frame 104. Redacted image files are pending upload to this repository. A further screenshot expanding ICMPv6 Type and Code would make the error evidence clearer.

## AI-augmented investigation workflow

I use AI as a complementary learning and analytical tool, not as an independent authority on security findings. In this case, AI supported the initial packet review, suggested display filters, helped explain protocol behavior and structured the technical report. I collected the capture and reproduced key views in Wireshark, supplying screenshots to check the proposed findings against actual packet evidence.

The workflow is evidence-first: inspect the source, use AI to explore explanations, verify key claims against packet fields, distinguish facts from hypotheses, and document remaining uncertainty. Sensitive network identifiers are excluded from public artifacts. Independent reproduction of all findings remains a learning objective; the screenshots do not establish that every initial claim has been manually verified.

## SOC triage conclusion

| Finding | Disposition |
|---|---|
| DNS resolution | Consistent with routine activity |
| TCP handshake | Established connection |
| Repeated ARP requests | Identify originating device |
| mDNS queries | Compatible with service discovery |
| ICMPv6 error | Investigate if recurrent |

No confirmed indicator of compromise was established. This is a baseline exercise, not a comprehensive security assessment.

## Limitations and next steps

- A short capture cannot establish long-term behavior or rule out compromise.
- Raw PCAPNG, local network identifiers and MAC addresses are withheld for privacy.
- Initial programmatic review did not use TShark; Wireshark screenshots provide subsequent manual validation.
- Add redacted screenshots, correlate DNS answers with actual connections and repeat using controlled benign and simulated suspicious traffic in an isolated lab.

## Resumo em português

Estudo de análise de tráfego real de uma rede pessoal, com 326 pacotes e aproximadamente 25,32 segundos de duração. Foram investigados ARP, DNS, TCP, TLS, QUIC, mDNS e ICMPv6. O objetivo é demonstrar metodologia de triagem SOC N1, interpretação de evidências e distinção entre fatos e hipóteses. Nenhum ataque foi confirmado. A captura original não foi publicada por privacidade.
