/*
    YARA Rules: ThreatActor Network IOC Detection
    Generated: 2026-03-22
    Source: GT-AX11000 Pro firewall log analysis

    Detects artifacts on endpoints that may indicate communication with
    known malicious IPs or scanning patterns observed in the threat analysis.
*/

rule ThreatActor_Bulgarian_Scanner_79_124_58_86
{
    meta:
        description = "Detects references to Bulgarian scanning IP 79.124.58.86 (AS41436)"
        author = "Velociraptor Claw Edition SOC"
        date = "2026-03-22"
        severity = "high"
        reference = "ThreatActor/skynet-0 (1).log — port scan TCP 48002, spoofed SEQ/ID"
        mitre_attack = "T1046 Network Service Discovery"

    strings:
        $ip_dotted = "79.124.58.86"
        $ip_hex = { 4F 7C 3A 56 }  // 79.124.58.86 in network byte order

    condition:
        any of them
}

rule ThreatActor_SSDP_Flood_Source_38_43_63_92
{
    meta:
        description = "Detects references to SSDP flood source 38.43.63.92 (Cogent)"
        author = "Velociraptor Claw Edition SOC"
        date = "2026-03-22"
        severity = "medium"
        reference = "ThreatActor/skynet-0 (1).log — UDP 5678 broadcast flood every 60s"
        mitre_attack = "T1498 Network Denial of Service"

    strings:
        $ip = "38.43.63.92"

    condition:
        $ip
}

rule Suspicious_Port_48002_Connection
{
    meta:
        description = "Detects config files, scripts, or logs referencing port 48002 (targeted by scanner)"
        author = "Velociraptor Claw Edition SOC"
        date = "2026-03-22"
        severity = "medium"
        mitre_attack = "T1571 Non-Standard Port"

    strings:
        $port_colon = ":48002"
        $port_eq = "=48002"
        $port_space = " 48002"

    condition:
        any of them
}

rule Suspicious_SYN_Scan_Indicators
{
    meta:
        description = "Detects log entries showing classic SYN scan signatures (Window=1024, same SEQ across retries)"
        author = "Velociraptor Claw Edition SOC"
        date = "2026-03-22"
        severity = "high"
        mitre_attack = "T1046 Network Service Discovery"

    strings:
        $win1024_syn = "WINDOW=1024" ascii
        $syn_flag = "SYN URGP=0" ascii
        $drop = "DROP IN=" ascii

    condition:
        all of them
}

rule SSDP_UPnP_Abuse_Port_5678
{
    meta:
        description = "Detects SSDP/UPnP abuse patterns on port 5678 in logs or configs"
        author = "Velociraptor Claw Edition SOC"
        date = "2026-03-22"
        severity = "low"
        mitre_attack = "T1557 Adversary-in-the-Middle"

    strings:
        $ssdp_port = "DPT=5678"
        $ssdp_bcast = "DST=255.255.255.255"
        $upnp = "SSDP" nocase

    condition:
        ($ssdp_port and $ssdp_bcast) or ($ssdp_port and $upnp)
}

rule Network_IOC_AWS_Relay_Probe
{
    meta:
        description = "Detects AWS relay probes from fixed source port 32099 (Tailscale/WireGuard coordination)"
        author = "Velociraptor Claw Edition SOC"
        date = "2026-03-22"
        severity = "info"
        reference = "Not necessarily malicious — VPN relay. Flag for awareness."

    strings:
        $sport = "SPT=32099"
        $aws1 = "13.56.9.112"
        $aws2 = "3.23.201.30"
        $aws3 = "54.164.145.238"

    condition:
        $sport and any of ($aws*)
}
