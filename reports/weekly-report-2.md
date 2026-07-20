# Weekly Report 2 --> Core Parsing & Detection Logic

## Focus
Moving from environment/research into actual code: project rename, initial commit, register mapping, and the first detection rules.

## Work Completed

**Project rename & restructure**
- Renamed the project from its working title "Pipeline Guard" to **GridWatch** and rewrote the README to match.
- Made the first real commit of application code, then reorganized the codebase into a proper `src/` layout and added a `.gitignore` (excluding `venv/`, `__pycache__/`, logs, and `.env`).

**Modbus register mapping**
- Identified the relevant GRFICSv3 Modbus register map by observing live traffic against the process simulation: Input Register 100 (reactor outlet valve position) and Input Register 108 (reactor pressure).
- Cross-checked this against an independent register-mapping writeup of the same GRFICSv3 environment register 108 matched exactly, which gave confidence the mapping was correct rather than assumed.

**Detection rule design**
- Designed four detection rules (R001–R004) and mapped each to a grounding standard (IEC 62443 / NERC CIP / NIST SP 800-82):
  - R001: reactor pressure exceeds a safe threshold while the outlet valve is closed (process-danger condition).
  - R002: a Modbus write command reaching the PLC from the DMZ network.
  - R003: a Modbus write from the Engineering Workstation to the PLC outside a defined maintenance window.
  - R004: an unrecognized IP address appearing on the ICS subnet.
- Implemented the Modbus TCP packet parser (`pyshark`-based) that extracts and correlates request/response pairs so register values can be tracked over time.

## Challenges & Fixes
- Found that `REG_VALVE_STATE` (register 100) was mislabeled in documentation as a Holding Register instead of an Input Register. Traced this through the code and git history and confirmed it was a documentation/threat-model labeling issue only the parser and rule-checking logic were already function-code-agnostic, so detection was never actually broken. Fixed the label and re-ran the full test suite (all passing before and after) to confirm no regression.

## Status at End of Week
Core parsing and all four detection rules implemented and passing tests locally, using synthetic/local packet capture. No cloud alerting yet, and no remote (cross-laptop) capture yet both were still open at this point.
