# Wazuh integration for netaudit

## Flow

1. Run audit and write NDJSON for the agent:

```powershell
netaudit audit --wazuh-file reports\wazuh-netaudit.json
```

2. On the **Wazuh agent** (same host or a collector), add the snippet from
   `ossec-localfile.conf.snippet` to `ossec.conf` and restart the agent.

3. On the **Wazuh manager**, merge `local_rules.xml` into
   `/var/ossec/etc/rules/local_rules.xml` and restart `wazuh-manager`.

4. Optional: push over syslog instead of a file:

```powershell
netaudit audit --wazuh-syslog 192.168.1.50 --wazuh-syslog-port 514
```

5. Optional: test API login (homelab):

```powershell
netaudit audit --wazuh-api https://WAZUH-MANAGER:55000 --wazuh-user wazuh --wazuh-pass '***'
```

## What you get in Wazuh

- Alerts for FortiGate any/any policies, weak SNMP, missing NTP/syslog
- SCALANCE XC208 ACL / telnet / syslog gaps
- Rule IDs `100500`–`100511` under group `netaudit`

Primary path is **agent localfile + JSON** (most reliable across Wazuh 4.x).
