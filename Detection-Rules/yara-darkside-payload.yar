rule APT_Ransomware_DarkSide_Payload {
    meta:
        description = "Detects DarkSide Ransomware payload strings and execution patterns (Colonial Pipeline scenario)"
        author = "Benedict M. Garcia (benben000000)"
        date = "2026-04-24"
        tlp = "RED"
        mitre_id = "T1486"
        hash = "1512301c92569f417da5c3a3c200593cc19f6a4"
    strings:
        // DarkSide specific ransom note string
        $s1 = "Welcome to DarkSide" ascii wide
        $s2 = "Your computers and servers are encrypted, private data was downloaded" ascii wide
        
        // Anti-recovery / Anti-analysis
        $cmd1 = "vssadmin.exe Delete Shadows /All /Quiet" nocase ascii wide
        $cmd2 = "powershell -ep bypass -c \"Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }\"" nocase ascii wide
        
        // Mutex or specific API imports commonly seen in this family
        $api1 = "CryptGenRandom" ascii
        $api2 = "NetShareEnum" ascii
    condition:
        uint16(0) == 0x5a4d and
        filesize < 2MB and
        (1 of ($s*) or 2 of ($cmd*)) and
        all of ($api*)
}
