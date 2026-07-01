# Pipeline Guard Requirements

## Functional Requirements

### FR-1 Asset Discovery

The system shall identify industrial assets through passive network monitoring.

---

### FR-2 Protocol Identification

The system shall identify industrial communication protocols.

---

### FR-3 Process-State Tracking

The system shall maintain an internal representation of process conditions.

---

### FR-4 Risk Assessment

The system shall evaluate observed actions against predefined engineering rules.

---

### FR-5 Alert Generation

The system shall generate alerts when unsafe operational conditions are detected.

---

### FR-6 Event Logging

The system shall maintain records of observed events and generated alerts.

---

## Non-Functional Requirements

### NFR-1 Passive Operation

The system shall not transmit industrial control commands.

---

### NFR-2 Scalability

The architecture shall support future expansion.

---

### NFR-3 Reliability

The monitoring platform shall continue operation despite individual service failures.

---

### NFR-4 Security

Communications with cloud services shall use encrypted channels.

---

## Assumptions

* GRFICSv3 provides a functioning OT environment.
* Docker containers remain operational.
* Network visibility is available.
* Industrial protocols are observable.

---

## Constraints

* Monitoring only.
* No PLC modification.
* No SCADA modification.
* No direct process interaction.
* Azure used only for storage and analytics.
