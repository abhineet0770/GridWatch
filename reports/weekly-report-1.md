# Weekly Report 1 — Environment Setup & Project Scaffolding

## Focus
Standing up the OT lab environment and laying down the initial project structure and research grounding.

## Work Completed

**Project scaffolding**
- Initialized the repository, added a documentation structure (`docs/`, `reports/`, `screenshots/`, `diagram/`, `notes/`), and drafted an initial architecture diagram.
- Wrote a first-pass README, architecture doc, and requirements doc under the project's working title, "Pipeline Guard."

**Lab environment**
- Deployed an Ubuntu VM (VirtualBox) on the primary lab laptop and installed Docker.
- Brought up the GRFICSv3 industrial control system testbed — all 7 containers (PLC, HMI, Engineering Workstation, router, process simulation, and supporting services) healthy and running.
- Connected a second laptop to the VM host via a dedicated crossover Ethernet cable, physically isolating the OT lab from the daily-driver network, and hardened SSH access to that link.
- Verified live Modbus TCP traffic on the ICS subnet via `tcpdump` and confirmed the lab actually produces observable industrial protocol traffic before writing a single line of parsing code.

**Research**
- Read into GRFICSv3's underlying simulation (a Tennessee Eastman-style exothermic reactor process) to understand what "normal" process behavior looks like.
- Started grounding the eventual detection logic in IEC 62443, NERC CIP, and NIST SP 800-82 — the standards the alert rules would later be mapped to.

## Challenges
- Docker network pool conflicts and a macvlan network mismatch during GRFICSv3 deployment, plus a missing Git LFS asset, all resolved before containers came up healthy.
- VirtualBox's 3D acceleration couldn't render GRFICSv3's optional visualization layer. Confirmed this visualization is non-essential to the project (it's not required for traffic generation or process simulation) and moved on rather than losing time chasing a GPU/driver rabbit hole.

## Status at End of Week
Lab environment fully operational and producing real, capturable Modbus TCP traffic. No application code written yet — this week was entirely environment and research groundwork.
