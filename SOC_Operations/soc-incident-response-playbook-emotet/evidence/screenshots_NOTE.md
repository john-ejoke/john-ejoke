# Screenshots

This folder will contain screenshots of each Splunk detection query firing against
the replayed event logs in a home lab environment.

## Planned Screenshots

| Query | Status |
|---|---|
| emotet_dropper.spl firing in Splunk | Pending lab setup |
| encoded_powershell.spl firing in Splunk | Pending lab setup |
| firewall_tamper.spl firing in Splunk | Pending lab setup |
| log_clearing.spl firing in Splunk | Pending lab setup |
| sam_access.spl firing in Splunk | Pending lab setup |
| full_chain_correlation.spl dashboard view | Pending lab setup |

## Lab Environment Plan

- Splunk Free Instance (local VM)
- Windows Server 2019 VM for log replay
- Replay the five scenario Event Log entries manually
- Capture each query returning the correct results

This is part of the continuous improvement documented in the Learning Notes
section of the main README.
