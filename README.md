# Network Audit and Config Backup

> **Beta · internal use only**  

Narzędzie CLI do **backupu konfiguracji** routerów/switchy/firewalli po SSH, **diffowania zmian**, **walidacji standardów** i **wykrywania niebezpiecznych ustawień**, z integracją **Wazuh**.

Targety produkcyjne / labowe: **FortiGate 120G**, **SCALANCE XC208**, Cisco IOS + eksport alertów do SIEM.

## Funkcje

| Funkcja | Opis |
|--------|------|
| **Backup SSH** | FortiGate (`show full-configuration`), SCALANCE XC208 (`show running-config`), Cisco IOS/ASA |
| **Wersjonowanie** | Snapshoty w `backups/<device>/<timestamp>.cfg` + `index.json` |
| **Diff** | Unified diff między backupami |
| **Audit** | Reguły per platforma: any/any, słabe SNMP, brak NTP/syslog, telnet, HTTP… |
| **Export** | Markdown + CSV |
| **Wazuh** | NDJSON dla agenta, syslog, opcjonalnie API |

## Platformy

| `platform` w inventory | Urządzenie | Komenda backupu |
|------------------------|------------|-----------------|
| `fortigate` / `fortios` | **FortiGate 120G** (i inne FG) | `show full-configuration \| grep .` |
| `scalance_xc` / `scalance` | **SCALANCE XC208** (XC-200) | `show running-config` |
| `cisco_ios` / `cisco_asa` | Cisco | `show running-config` |

## Szybki start (demo bez sprzętu)

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

## FortiGate 120G + SCALANCE XC208 (produkcja)

`inventory.yaml`:

```yaml
devices:
  - name: fg-120g-01
    host: 192.168.10.1
    device_type: firewall
    platform: fortigate
    username: admin
    password: "sekret"
    port: 22

  - name: scalance-xc208-01
    host: 192.168.20.10
    device_type: switch
    platform: scalance_xc
    username: admin
    password: "sekret"
    port: 22
```

```powershell
netaudit backup
netaudit audit --export reports\audit.md --csv reports\audit.csv `
  --wazuh-file reports\wazuh-netaudit.json
netaudit diff fg-120g-01
```

## Wazuh

1. Audyt zapisuje eventy NDJSON:
   ```powershell
   netaudit audit --wazuh-file reports\wazuh-netaudit.json
   ```
2. Na agencie Wazuh dodaj snippet z `integrations/wazuh/ossec-localfile.conf.snippet` i zrestartuj agenta.
3. Na managerze wklej reguły z `integrations/wazuh/local_rules.xml` do `local_rules.xml`, zrestartuj manager.
4. Opcjonalnie syslog:
   ```powershell
   netaudit audit --wazuh-syslog 192.168.1.50 --wazuh-syslog-port 514
   ```

Szczegóły: [`integrations/wazuh/README.md`](integrations/wazuh/README.md).

## Reguły audytu (skrót)

**FortiGate:** `FG-POLICY-ANY-ANY`, `FG-SNMP-WEAK`, `FG-NTP-MISSING`, `FG-SYSLOG-MISSING`, `FG-TELNET-ADMIN`, `FG-HTTP-ADMIN`…

**SCALANCE XC208:** `SC-ACL-PERMIT-ANY`, `SC-SNMP-WEAK`, `SC-NTP-MISSING`, `SC-SYSLOG-MISSING`, `SC-TELNET-ENABLED`…

**Cisco:** `ACL-PERMIT-ANY`, słabe SNMP, brak NTP/syslog, telnet, type 7, VTY bez ACL…

Pliki: `netaudit/rules/{default,fortigate,scalance}.yaml`

## Testy

```powershell
pytest -q
```
