/*
 * YARA Detection Rule — DarkSide Ransomware
 * ==========================================
 * Author:      Ejoke John
 * Date:        2025-07-01
 * Version:     1.0
 * Reference:   https://attack.mitre.org/groups/G0139/
 * SHA-256:     156335b95ba216456f1ac0894b7b9d6ad95404ac7df447940f21646ca0090673
 *
 * Description:
 *   Detects DarkSide ransomware based on eight behavioural indicators identified
 *   through threat intelligence analysis and MITRE ATT&CK G0139 correlation.
 *   Indicators include ransom note artifacts, persistence mechanisms, shadow copy
 *   deletion commands, obfuscated PowerShell execution, and registry auto-run paths.
 *
 *   Detection triggers on 3 or more matches for broad coverage.
 *   Increase to 4+ in low-noise environments to reduce false positive risk.
 *
 * Validated Against:
 *   - Positive: Synthetic DarkSide behavioural test file (samplefile.txt)
 *   - Negative: Benign comparison samples (0 false positives)
 *
 * References:
 *   - CISA Advisory AA21-131A
 *   - MITRE ATT&CK Group G0139 (CARBON SPIDER / DarkSide)
 *   - VirusTotal report for confirmed sample hash
 */

rule DarkSide_Ransomware
{
    meta:
        description     = "Detects DarkSide ransomware based on behavioural indicators"
        author          = "Ejoke John"
        date            = "2025-07-01"
        version         = "1.0"
        sha256          = "156335b95ba216456f1ac0894b7b9d6ad95404ac7df447940f21646ca0090673"
        mitre_group     = "G0139"
        mitre_tactics   = "TA0002, TA0003, TA0005, TA0007, TA0040"
        reference       = "https://attack.mitre.org/groups/G0139/"
        cisa_advisory   = "AA21-131A"
        tlp             = "WHITE"

    strings:
        // Ransom note filename dropped in every encrypted directory
        $note           = "README_RECOVER_FILES.txt" ascii wide

        // File extensions appended to encrypted files
        $ext_locked     = ".locked" ascii wide
        $ext_darkside   = ".darkside" ascii wide

        // Fake service name created for persistence (T1543.003)
        $svc            = "SysUpdateSvc" ascii wide

        // Shadow copy deletion to prevent recovery (T1490)
        $vss            = "vssadmin delete shadows" ascii wide nocase

        // Obfuscated PowerShell execution (T1027, T1059.001)
        $ps             = "powershell -enc" ascii wide nocase

        // Privilege discovery command (T1057)
        $whoami         = "cmd.exe /c whoami" ascii wide nocase

        // Scheduled task creation for persistence (T1053.005)
        $schtask        = "schtasks /create /tn" ascii wide nocase

        // Registry auto-start path for persistence (T1547.001)
        $regpath        = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide

    condition:
        // Trigger on 3 or more behavioural indicators
        // Tune to 4 of them for stricter detection in production environments
        3 of them
}


/*
 * Supplementary Rule — DarkSide High-Confidence Detection
 * ========================================================
 * Stricter variant requiring the ransom note AND at least 3 additional indicators.
 * Recommended for use in SIEM/EDR platforms where precision is critical.
 */

rule DarkSide_Ransomware_HighConfidence
{
    meta:
        description     = "High-confidence DarkSide detection: ransom note + 3 behavioural indicators"
        author          = "Ejoke John"
        date            = "2025-07-01"
        version         = "1.0"
        sha256          = "156335b95ba216456f1ac0894b7b9d6ad95404ac7df447940f21646ca0090673"
        mitre_group     = "G0139"
        tlp             = "WHITE"

    strings:
        $note           = "README_RECOVER_FILES.txt" ascii wide
        $vss            = "vssadmin delete shadows" ascii wide nocase
        $svc            = "SysUpdateSvc" ascii wide
        $ps             = "powershell -enc" ascii wide nocase
        $schtask        = "schtasks /create /tn" ascii wide nocase
        $regpath        = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $whoami         = "cmd.exe /c whoami" ascii wide nocase
        $ext_darkside   = ".darkside" ascii wide

    condition:
        // Ransom note must be present AND at least 3 other behavioural indicators
        $note and 3 of ($vss, $svc, $ps, $schtask, $regpath, $whoami, $ext_darkside)
}
