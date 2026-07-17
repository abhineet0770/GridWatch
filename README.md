# GridWatch

Passive OT/ICS network monitoring and process-aware risk assessment, built against GRFICSv3.

GridWatch is a research-oriented Operational Technology (OT) cybersecurity project that passively monitors Modbus TCP traffic in a simulated industrial control system, correlates it against process state and known-good network behavior, and raises alerts grounded in IEC 62443, NERC CIP, and NIST SP 800-82 to an Azure-based alerting pipeline. It is not intended to replace commercial OT security products — it's a research, learning, and implementation exercise.

## Project Motivation

Industrial environments differ from traditional IT networks because cyber events can directly affect physical processes. Modern OT security platforms provide visibility into industrial assets, communications, and operational risk. GridWatch was built to explore that workflow hands-on: industrial protocols, passive network monitoring, process behavior, and engineering-driven risk assessment.

## Architecture


<img width="1606" height="979" alt="ChatGPT Image Jul 17, 2026, 05_05_42 PM" src="https://github.com/user-attachments/assets/8758d214-6798-4598-bc0e-d3d592ff9423" />


Two physical laptops connected via crossover Ethernet, isolating the OT lab from the daily-driver network:

- **Laptop A ("witcher")** — hosts an Ubuntu VM running GRFICSv3 (7 Docker containers: PLC, EWS, HMI, router, process simulation, plus Caldera and Kali).
- **Laptop B ("beast")** — runs GridWatch itself.

GridWatch reaches the VM over an SSH jump chain (Laptop B → Laptop A → VM) and captures traffic from inside the `plc` container's own network namespace via `docker exec`, which is required because Docker's macvlan networking doesn't expose same-subnet sibling container traffic (e.g. PLC↔EWS) to any external host-level capture. Capture is fully passive — no active Modbus polling, no control commands ever transmitted.

## Modbus Register Map (GRFICSv3)

| Register | Meaning | Used by GridWatch |
|---|---|---|
| IR 100 | Reactor outlet valve position (read-only) | R001 |
| IR 108 | Reactor pressure (kPa) | R001 |

## Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| R001 | Reactor pressure exceeds threshold while outlet valve is closed | CRITICAL |
| R002 | Modbus write (FC06/FC16) to the PLC originating from the DMZ | CRITICAL |
| R003 | EWS write to the PLC outside the configured maintenance window | HIGH |
| R004 | Unrecognized IP address appears on the ICS subnet | HIGH |

Alert deduplication is state-change-aware, with a cooldown window sized against ISA-18.2 / EEMUA-191 industrial alarm-rate benchmarks — this prevents alert flooding without suppressing genuine state changes.

## Alerting Pipeline

Triggered alerts are uploaded as JSON to an Azure Blob Storage container, which fires an Event Grid subscription on blob creation, which triggers a Logic App that parses the alert and sends an email notification.

## Project Status

### Completed
- GRFICSv3 lab fully deployed (7 healthy Docker containers), two-laptop crossover-Ethernet-isolated setup
- Passive Modbus TCP parsing (local and remote/SSH-based capture)
- Detection rules R001–R004 implemented
- Alert deduplication / rate-limiting layer
- Azure Blob Storage → Event Grid → Logic App → email pipeline, live-tested end-to-end
- R004 confirmed live against real unscripted network traffic
- Automated test suite (11 tests)

### In Progress
- R001 live-fire validation (reactor pressure / valve state)
- R002 and R003 live-fire validation (currently unit-tested only)

### Planned
- Final report / writeup
- Codebase cleanup pass

## Setup

Copy `.env.example` to `.env` and fill in your Azure Storage connection string. Copy the relevant keys from `config.example.py` into `config.py`'s remote-capture section with your own lab's IPs/usernames — these are deliberately not committed.

## Testing

```
pytest src/tests/
```

11 tests covering rule detection, deduplication, packet parsing (local and remote), and Azure upload mocking.

## Repository Structure

```
gridwatch/
├── README.md
├── config.example.py
├── docs/
├── reports/
├── screenshots/
├── diagram/
├── notes/
└── src/
```

## Learning Goals

- Operational Technology (OT) Security
- Industrial Control Systems (ICS)
- Industrial Network Monitoring
- Process-Aware Security Concepts
- Risk Assessment Methodologies (IEC 62443 / NERC CIP / NIST SP 800-82)
- Industrial Cybersecurity Research
- Dockerized OT Environments
- Cloud Integration for OT Alerting (Azure)

## Author

**Abhineet Tandon**
B.Tech Computer Science and Engineering (Cybersecurity), UPES Dehradun
OT Security Intern, OilSERV

Research Interests: OT Security · Industrial Cybersecurity · Network Monitoring · Process-Aware Detection

## Acknowledgments

This project uses [GRFICSv3](https://github.com/Fortiphyd/GRFICSv3), an open-source OT/ICS security lab developed by Fortiphyd Logic (originally with Georgia Tech). GRFICS is not affiliated with or endorsing this project.

Citation: Formby, D., Rad, M., and Beyah, R. "Lowering the Barriers to Industrial Control System Security with GRFICS." USENIX Workshop on Advances in Security Education (ASE 18).
