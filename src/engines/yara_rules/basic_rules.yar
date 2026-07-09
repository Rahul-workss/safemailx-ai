rule Suspicious_PowerShell_Obfuscation {
    meta:
        description = "Detects basic PowerShell execution and encoding flags often used in malicious macros."
        author = "SafeMail X AI Default Rules"
        severity = "High"
    strings:
        $ps1 = "powershell.exe" ascii wide nocase
        $ps2 = "pwsh.exe" ascii wide nocase
        $enc1 = "-enc" ascii wide nocase fullword
        $enc2 = "-EncodedCommand" ascii wide nocase
        $byp1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $byp2 = "-ep bypass" ascii wide nocase
        $hidden = "-WindowStyle Hidden" ascii wide nocase
        $w  = "-w hidden" ascii wide nocase
    condition:
        any of ($ps*) and (any of ($enc*) or any of ($byp*) or any of ($hidden) or $w)
}

rule Suspicious_VBA_AutoOpen {
    meta:
        description = "Detects automatic execution triggers inside Office documents combined with suspicious keywords."
        author = "SafeMail X AI Default Rules"
        severity = "Medium"
    strings:
        $auto1 = "AutoOpen" ascii wide nocase
        $auto2 = "Workbook_Open" ascii wide nocase
        $auto3 = "Document_Open" ascii wide nocase
        $sus1 = "Shell" ascii wide nocase fullword
        $sus2 = "WScript.Shell" ascii wide nocase
        $sus3 = "CreateObject" ascii wide nocase
    condition:
        any of ($auto*) and any of ($sus*)
}
