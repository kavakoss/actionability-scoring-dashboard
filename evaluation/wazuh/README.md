# Wazuh detection rules — v1 (frozen 2026-10-08)

Detection layer used to generate the seed alerts scored by the dashboard. Three
techniques: **T1059.001** (PowerShell), **T1059.003** (Windows Command Shell),
**T1105** (Ingress Tool Transfer). Seeds are `rule.level >= 15`; supporting
evidence is still retrieved from any level via case expansion.

`local_rules.xml` here is a sanitized copy of
`/var/ossec/etc/rules/local_rules.xml` on the Wazuh server (agent
`WIN-THESIS-01`, host KevinPad).

## Rules

| Rule | Level | Fires on | Notes |
|---|---:|---|---|
| 100100 | 15 | Sysmon EID 1, `powershell/pwsh.exe` + switch/expression/dowload token | T1059.001 |
| 100101 | 15 | Sysmon EID 1, `cmd.exe` + `/c /r /k echo\|whoami\|cmd<` or `.bat/.cmd/.vbs` or input redirection | T1059.003 |
| 100102 | 15 | Sysmon EID 1, command line with web-request / download primitives | T1105 |
| 100103 | 15 | Sysmon EID 1, `certutil/certreq/curl/wget/bitsadmin/MpCmdRun/OneDrive…` + transfer switch | T1105 |
| 100104 | 15 | Sysmon EID 3, network connection from a transfer-capable process | T1105 |

Suppression (level 0) rules keep recurring benign activity from becoming
critical. They are intentionally narrow — one exact parent/command signature
each:

| Rule | Parent | Suppresses |
|---|---|---|
| 100105 | 100101 | Intel SUR scheduled task (`wscript` → `task.bat`) |
| 100106 | 92058 | PcaSvc background compatibility check (`sdbinst -m -bg`) |
| 100107 | 100100 | Wazuh agent's own PowerShell health checks |
| 100108 | 100101 | Windows `hpatchmonTask.cmd` scheduled task |
| 100109 | 100101 | Browser security-extension helpers (Chrome → ESET/Total Security) |

## Deploy

```bash
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t      # must exit 0
sudo systemctl restart wazuh-manager
```

Verify suppression with a real event from `alerts.json`: the child rule must
match the same `win.eventdata.*` values. Note that path fields in stored alerts
contain **doubled backslashes**, so patterns should avoid a leading `\\`.

## Known limitations (state in the thesis)

- Rules were tuned **after** observing the same ART runs used for evaluation.
  Freeze this version before final numbers; do not re-tune per variation.
- Rules are host-agnostic and untested against broad real-world traffic.
- T1059.001 variation 1 (`#18` Invoke Known Malicious Cmdlets) and variation 3
  (`#19/#7/#8`) were not detected by these rules in the October run — report
  that as a detection-coverage result, not a defect to patch away.
