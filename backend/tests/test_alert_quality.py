from alert_quality import classify_known_benign, exclude_known_benign


def _alert(rule_id, image, command_line, parent_image, parent_command_line):
    return {
        "rule": {"id": rule_id, "level": 15},
        "data": {
            "win": {
                "eventdata": {
                    "image": image,
                    "commandLine": command_line,
                    "parentImage": parent_image,
                    "parentCommandLine": parent_command_line,
                }
            }
        },
    }


def test_excludes_confirmed_chrome_security_extension_cmd_signature():
    alert = _alert(
        "100101",
        r"C:\Windows\System32\cmd.exe",
        r'cmd.exe /c "C:\Program Files\ESET\Total Security 21.3\bridge.exe" '
        "chrome-extension://ahkjpbeeocnddjkakilopmfdlnjdpcdm/ --parent-window=0",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
    )

    assert classify_known_benign(alert) == "Chrome security extension launching CMD"


def test_chrome_cmd_near_match_is_retained():
    alert = _alert(
        "100101",
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe /c whoami",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "chrome.exe",
    )

    assert classify_known_benign(alert) is None


def test_excludes_exact_intel_sur_wscript_batch_signature():
    alert = _alert(
        "100101",
        r"C:\Windows\System32\cmd.exe",
        r'"C:\Windows\System32\cmd.exe" /c '
        r'"C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.bat"',
        r"C:\Windows\System32\wscript.exe",
        r'"C:\Windows\System32\wscript.exe" //B //NoLogo '
        r'"C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.vbs"',
    )

    assert classify_known_benign(alert) == "Intel SUR scheduled maintenance task"


def test_excludes_exact_pcasvc_sdbinst_signature():
    alert = _alert(
        "92058",
        r"C:\WINDOWS\System32\sdbinst.exe",
        r"C:\WINDOWS\System32\sdbinst.exe -m -bg",
        r"C:\WINDOWS\system32\svchost.exe",
        r"C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc",
    )

    assert classify_known_benign(alert) == "PcaSvc background compatibility check"


def test_sdbinst_with_different_parent_is_retained():
    alert = _alert(
        "92058",
        r"C:\WINDOWS\System32\sdbinst.exe",
        r"C:\WINDOWS\System32\sdbinst.exe -m -bg",
        r"C:\Temp\unknown.exe",
        r"C:\Temp\unknown.exe",
    )

    assert classify_known_benign(alert) is None


def test_exclusion_counts_are_returned_without_mutating_alerts():
    benign = _alert(
        "100101",
        r"C:\Windows\System32\cmd.exe",
        r'"C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.bat"',
        r"C:\Windows\System32\wscript.exe",
        r'"C:\Program Files\Intel\SUR\QUEENCREEK\x64\task.vbs"',
    )
    suspicious = _alert(
        "100101",
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe /c whoami",
        r"C:\Windows\System32\powershell.exe",
        "powershell.exe",
    )

    included, excluded = exclude_known_benign([benign, suspicious])

    assert included == [suspicious]
    assert excluded == {"Intel SUR scheduled maintenance task": 1}
    assert benign["rule"]["level"] == 15
