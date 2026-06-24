# Pipeline Guard

### Passive OT Monitoring and Process-Aware Risk Assessment using GRFICSv3

Pipeline Guard is a research-oriented Operational Technology (OT) cybersecurity project focused on studying and implementing the core concepts behind modern industrial monitoring platforms.

The project utilizes the GRFICSv3 industrial control system testbed to simulate a realistic oil pipeline environment and serve as a foundation for developing a passive monitoring solution capable of asset discovery, process-state awareness, and process-aware risk assessment.

---

## Project Motivation

Industrial environments differ significantly from traditional IT networks because cyber events can directly affect physical processes.

Modern OT security platforms provide visibility into industrial assets, communications, and operational risks. Understanding how these systems function requires knowledge of industrial protocols, network monitoring, process behavior, and engineering-driven risk assessment.

Pipeline Guard was created as a practical research project to explore these concepts in a realistic environment and better understand the workflow behind process-aware industrial monitoring systems.

> The project is not intended to replace commercial OT security products. Instead, it serves as a research, learning, and implementation exercise focused on understanding how industrial monitoring platforms operate within real-world control environments.

---
## Architecture Overview
<img width="453" height="654" alt="Purdue model for our Project" src="https://github.com/user-attachments/assets/d4d7589e-1093-47db-af3d-3ed8ac762f95" />

---

## Project Objectives

| Objective                  | Description                                         |
| -------------------------- | --------------------------------------------------- |
| Industrial Control Systems | Study ICS and OT architectures                      |
| Network Monitoring         | Analyze industrial communications                   |
| Asset Discovery            | Explore passive identification of industrial assets |
| Process Awareness          | Understand process-state monitoring concepts        |
| Risk Assessment            | Investigate engineering-rule-based detection        |
| Practical Experience       | Gain hands-on OT cybersecurity experience           |

---

## Current Architecture

```text
ASUS Laptop
│
├── Windows 11
│
└── Ubuntu Virtual Machine
    │
    └── GRFICSv3
        ├── PLC
        ├── HMI
        ├── Engineering Workstation
        ├── Router
        ├── Industrial Network
        └── Process Simulation

Dell Laptop
│
└── Pipeline Guard (Planned)
```

*Architecture diagram will be added as the project progresses.*

---

## Project Status

### Completed

| Status | Task                                      |
| ------ | ----------------------------------------- |
| ✅      | GitHub repository initialization          |
| ✅      | Ubuntu virtual machine deployment         |
| ✅      | Docker installation and validation        |
| ✅      | GRFICSv3 deployment                       |
| ✅      | Network configuration and troubleshooting |
| ✅      | Environment validation                    |
| ✅      | Initial project architecture design       |

### In Progress

| Status | Task                                    |
| ------ | --------------------------------------- |
| 🔄     | GRFICSv3 architecture analysis          |
| 🔄     | Industrial network mapping              |
| 🔄     | Process understanding and documentation |
| 🔄     | Monitoring platform design              |

### Planned

| Status | Task                           |
| ------ | ------------------------------ |
| ⏳      | Passive asset discovery module |
| ⏳      | Process-state tracking module  |
| ⏳      | Risk assessment engine         |
| ⏳      | Alert generation framework     |
| ⏳      | Azure integration              |
| ⏳      | Testing and validation         |

---

## Development Roadmap

| Phase                          | Status         |
| ------------------------------ | -------------- |
| Environment Setup & Deployment | ✅ Completed    |
| Architecture Analysis          | 🔄 In Progress |
| Asset Discovery Design         | ⏳ Planned      |
| Process-State Tracking Design  | ⏳ Planned      |
| Risk Assessment Engine         | ⏳ Planned      |
| Alert Generation               | ⏳ Planned      |
| Azure Integration              | ⏳ Planned      |
| Testing & Validation           | ⏳ Planned      |
| Final Documentation            | ⏳ Planned      |

---

## Current Environment

| Category         | Technology        |
| ---------------- | ----------------- |
| Virtualization   | Oracle VirtualBox |
| Operating System | Ubuntu Linux      |
| Containerization | Docker            |
| OT Testbed       | GRFICSv3          |

---

## Repository Structure

```text
pipeline-guard/
│
├── README.md
├── docs/
├── reports/
├── screenshots/
├── diagram/
├── notes/
└── src/
```

---

## Learning Goals

Through this project, the following areas are being explored:

* Operational Technology (OT) Security
* Industrial Control Systems (ICS)
* Industrial Network Monitoring
* Process-Aware Security Concepts
* Risk Assessment Methodologies
* Industrial Cybersecurity Research
* Dockerized OT Environments

---

## Author

**Abhineet Tandon**

B.Tech Computer Science and Engineering
UPES Dehradun

**Research Interests**

* OT Security
* Industrial Cybersecurity
* Network Monitoring
* Process-Aware Detection
