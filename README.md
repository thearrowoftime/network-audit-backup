# scanmedaddy

> **BETA**  
> It is published as a **beta** reference - not a supported public product. Do not use against systems you do not own or administer.

CLI tool for **configuration backup** of routers/switches/firewalls over SSH, **change diffing**, **standards validation**, and **detection of unsafe settings**, with **Wazuh** integration.

Production: **FortiGate 120G**, **SCALANCE XC208**, alert export to SIEM.

## Features

| Feature | Description |
|-----------------------|
| **SSH backup** | FortiGate (`show full-configuration`), SCALANCE XC208 (`show running-config`) |
| **Versioning** | Snapshots under `backups/<device>/<timestamp>.cfg` + `index.json` |
| **Diff** | Unified diff between backups |
| **Audit** | Per-platform rules: any/any, weak SNMP, missing NTP/syslog, telnet, HTTP, ... |
| **Export** | Markdown + CSV |
| **Wazuh** | NDJSON for the agent, syslog, optional API |

## Platforms

| `platform` in inventory | Device | Backup command |
|-------------------------|--------|----------------|
| `fortigate` / `fortios` | **FortiGate 120G** (and other FG models) | `show full-configuration \| grep .` |
| `scalance_xc` / `scalance` | **SCALANCE XC208** (XC-200) | `show running-config` |
| `cisco_ios` / `cisco_asa` | Cisco | `show running-config` |

## Quick start (demo without hardware)

```powershell
cd C:\Users\marci\Projects\network-audit-backup
.\.venv\Scripts\Activate.ps1
pip install -e .
pip install pytest

netaudit backup --demo

# FortiGate 120G sample
netaudit audit --file samples\fg-120g-01.cfg --platform fortigate `
  --export reports\fg-audit.md --wazuh-file reports\wazuh-netaudit.json

# SCALANCE XC208 sample
netaudit audit --file samples\scalance-xc208-01.cfg --platform scalance_xc `
  --export reports\xc208-audit.md --wazuh-file reports\wazuh-netaudit.json
```

## FortiGate 120G + SCALANCE XC208 (live devices)

`inventory.yaml`:

```yaml
devices:
  - name: fg-120g-01
    host: 192.168.10.1
    device_type: firewall
    platform: fortigate
    username: admin
    password: "CHANGE_ME"
    port: 22

  - name: scalance-xc208-01
    host: 192.168.20.10
    device_type: switch
    platform: scalance_xc
    username: admin
    password: "CHANGE_ME"
    port: 22
```

```powershell
netaudit backup
netaudit audit --export reports\audit.md --csv reports\audit.csv `
  --wazuh-file reports\wazuh-netaudit.json
netaudit diff fg-120g-01
```

## Wazuh

1. Audit writes NDJSON events:
   ```powershell
   netaudit audit --wazuh-file reports\wazuh-netaudit.json
   ```
2. On the Wazuh agent, add the snippet from `integrations/wazuh/ossec-localfile.conf.snippet` and restart the agent.
3. On the manager, merge rules from `integrations/wazuh/local_rules.xml` into `local_rules.xml`, then restart the manager.
4. Optional syslog:
   ```powershell
   netaudit audit --wazuh-syslog 192.168.1.50 --wazuh-syslog-port 514
   ```

## Audit rules (summary)

**FortiGate:** `FG-POLICY-ANY-ANY`, `FG-SNMP-WEAK`, `FG-NTP-MISSING`, `FG-SYSLOG-MISSING`, `FG-TELNET-ADMIN`, `FG-HTTP-ADMIN`, ...

**SCALANCE XC208:** `SC-ACL-PERMIT-ANY`, `SC-SNMP-WEAK`, `SC-NTP-MISSING`, `SC-SYSLOG-MISSING`, `SC-TELNET-ENABLED`, ...

**Cisco:** `ACL-PERMIT-ANY`, weak SNMP, missing NTP/syslog, telnet, type 7, VTY without ACL, ...

Rule files: `netaudit/rules/{default,fortigate,scalance}.yaml`

## Tests

```powershell
pytest -q
```
