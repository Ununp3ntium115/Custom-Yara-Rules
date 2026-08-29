rule SUSP_Memfd_Perl_Loader
{
    meta:
        description = "Fileless memfd_create and argv[0]-spoofing Perl loader"
        reference = "https://github.com/hackerschoice/gsocket/blob/beta/deploy/deploy.sh"
        author = "Peter Gabaldon"
        date = "2026-08-23"
        severity = "high"
        note = "Dual-use: matches the decoded incident hook and upstream gsocket deploy.sh"
        yarahub_reference_link = "https://gist.github.com/PeterGabaldon/e5b9a6c4ad4e3278481fb5cb02d67a8c"
        yarahub_reference_md5 = "9f81e196548efc844bd8c407a0be834c"
        yarahub_uuid = "3ca2ee05-9464-4a4d-a444-9a8958433f41"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $fd = "$^F=255"
        $sysc = "for(319,279,385,4314,4354)"
        $memfd = "syscall$_,$\","
        $procfd = "/proc/$$/fd/"
        $exec = "exec{\"/proc/$$/fd/"

    condition:
        filesize < 10 MB
        and $sysc
        and 2 of ($fd, $memfd, $procfd, $exec)
}
