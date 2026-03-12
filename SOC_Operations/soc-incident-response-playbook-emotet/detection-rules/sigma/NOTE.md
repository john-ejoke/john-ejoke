# SIGMA Rules

SIGMA conversions for all six detection queries are in progress.

SIGMA is a platform-agnostic detection format that allows the same rule to be
converted into SPL (Splunk), KQL (Microsoft Sentinel), Elastic Query DSL, and
others without rewriting from scratch.

## Planned SIGMA Rules

| SPL File | SIGMA Status |
|---|---|
| emotet_dropper.spl | In progress |
| encoded_powershell.spl | In progress |
| firewall_tamper.spl | In progress |
| log_clearing.spl | In progress |
| sam_access.spl | In progress |
| full_chain_correlation.spl | In progress |

## Tools I am Using to Learn SIGMA

- [Sigma HQ GitHub](https://github.com/SigmaHQ/sigma)
- [Uncoder.IO](https://uncoder.io/) - browser-based SIGMA to SPL converter
- [pySigma](https://github.com/SigmaHQ/pySigma) - Python library for rule conversion

This folder will be updated as I complete each conversion.
