# Weekly Report 3 --> Cloud Alerting, Remote Capture & Live Validation

## Focus
Wiring GridWatch up to a real alerting pipeline, moving capture off a single machine and onto the two-laptop lab architecture, taming alert volume, and starting live-fire validation of the detection rules.

## Work Completed

**Azure alerting pipeline**
- Built and deployed an Azure Blob Storage → Event Grid → Logic App pipeline: triggered alerts are uploaded as JSON to a Blob container, which fires an Event Grid subscription on blob creation, which triggers a Logic App that parses the alert and sends an email notification.
- Live-tested the full pipeline end to end with a manual test blob and confirmed the email notification fires correctly.

**Remote (two-laptop) capture**
- Implemented remote capture over an SSH jump chain across the lab's two laptops, piping a remote `tcpdump` stream into a local `tshark` subprocess for parsing.
- Discovered that Docker's macvlan networking does not expose same-subnet sibling container traffic (e.g. PLC↔Engineering Workstation) to any external, host-level packet capture, not even in promiscuous mode. This is standard macvlan behavior, not a misconfiguration.
- Root-caused and confirmed the working fix: capturing from *inside* the PLC container's own network namespace (rather than at the VM host level) does see this traffic.

**Alert deduplication**
- Added a deduplication/rate-limiting layer so repeated firings of the same condition don't flood the alert pipeline: first occurrence always alerts, a genuine state change always alerts, and repeated identical firings are gated behind a cooldown window.
- Sized the cooldown window and R001's pressure deadband against published industrial alarm-management benchmarks (ISA-18.2 / EEMUA-191) rather than picking arbitrary numbers, and cross-referenced Suricata's alert-thresholding model as the closest analog from network security tooling.
- Validated this against real, unscripted network activity: R004 fired repeatedly against genuine scanning traffic on the lab network, and deduplication correctly collapsed what would otherwise have been a flood into a small number of legitimate per-source alerts.

**Bug fix — test suite polluting production data**
- Found that several rule-detection tests were calling into the alerting code path without mocking the Azure upload call, meaning every test run was silently uploading real test alerts into the live Blob Storage container. Patched the tests to mock the upload call, then cleaned the stale test-artifact blobs out of the storage container.

**Live-fire validation — in progress**
- Began live-fire testing of R001 (reactor pressure vs. valve state) by manipulating the simulated process directly. The test run was inconclusive and paused mid-session before a result was confirmed.
- On review, found the remote capture code was actually still using the older, host-level `tcpdump` approach and the exact approach already shown not to see PLC↔Engineering-Workstation traffic, rather than the container-namespace fix. This likely explains why the R001 test hadn't produced a result.
- Implemented the fix (capturing via the container's own namespace instead of the VM host), added configuration placeholders for it, corrected a stale example environment file that referenced an unused variable, and added test coverage for the remote-capture parsing and command-construction logic. All tests passing locally.
- **Not yet done:** deploying this fix to the lab machines and re-running the R001 live-fire test to confirm it actually resolves the issue.

## Status at End of Week
Cloud alerting, remote capture, and deduplication are all built and at least partially live-validated (R004 confirmed against real traffic). R001 is implemented but not yet confirmed live. R002 and R003 remain unit-tested only, no live-fire validation attempted yet.

## Next Steps
- Deploy the remote-capture fix to the lab and confirm R001 fires correctly against live traffic.
- Live-fire validate R002 (DMZ write to PLC) and R003 (Engineering Workstation write outside the maintenance window).
- General codebase cleanup pass (remove dead/unused files, tidy scratch artifacts).
- Begin the written report / documentation pass.
