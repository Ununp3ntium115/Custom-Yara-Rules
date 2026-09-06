rule Redtail_Installer_Script
{
    meta:
        description = "RedTail botnet multi-arch installer script - selects arch, finds writable+exec dir avoiding noexec, unpacks redtail.<arch>, runs with ssh propagation arg"
        author = "p0tatosmash3r"
        date = "2026-09-05"
        yarahub_author_twitter = ""
        yarahub_reference_link = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.redtail"
        yarahub_reference_md5 = "224b41af1717915304b30540473b8db2"
        yarahub_uuid = "a80a0cb5-6889-4dfa-9ba4-63dd280bac5e"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $rt1 = "redtail.$ARCH" ascii
        $rt2 = "redtail.$a" ascii
        $rt3 = "mv -f \"$CURR\"/redtail.*" ascii
        $rt4 = "rm -rf redtail.*" ascii
        $rt5 = ".redtail" ascii
        $arch_list = "for a in x86_64 i686 arm8 arm7 riscv" ascii
        $noexec1 = "get_noexec_dirs" ascii
        $noexec2 = "findmnt -rn -O noexec -o TARGET" ascii
        $exec_ssh = "./$FILENAME ssh" ascii
        $randfn = "openssl rand -base64 256" ascii
    condition:
        filesize < 8KB
        and (
            (2 of ($rt1, $rt2, $rt3, $rt4))
            or ($arch_list and 1 of ($noexec1, $noexec2))
            or ($rt5 and $exec_ssh and $randfn)
        )
}
