rule DDoSAgent_Linux_Cron_Persistence
{
    meta:
        description = "Linux DDoS bot (MalwareBazaar: DDoSAgent) - cron and rc.d persistence"
        author = "p0tatosmash3r"
        date = "2026-09-05"
        hash = "6f45c6d9c70d97f695cb7bbef362812a17f8ed4d37dafc342c26c86ed9b43638"
        yarahub_reference_link = "https://bazaar.abuse.ch/browse/signature/DDoSAgent/"
        yarahub_reference_md5 = "a61c7df581f75d60be370e20d4f91be2"
        yarahub_uuid = "633aac6c-20f5-42a9-b995-a79dd46ad791"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $cron1 = "/etc/cron.hourly/gcc.sh" ascii
        $cron2 = "*/3 * * * * root" ascii
        $cron_sed = "sed -i" ascii
        $rc1 = "/etc/rc%d.d/S90" ascii
        $rc2 = "/etc/rc.d/rc%d.d/S90" ascii
        $initd = "/etc/init.d/%s" ascii
        $dns1 = "8.8.8.8" ascii
        $dns2 = "8.8.4.4" ascii
        $path = "/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin" ascii
    condition:
        uint32(0) == 0x464c457f
        and filesize < 500KB
        and (
            ($cron1 and ($cron2 or $cron_sed))
            or (2 of ($rc1, $rc2, $initd))
            or ($path and $dns1 and $dns2)
        )
}
