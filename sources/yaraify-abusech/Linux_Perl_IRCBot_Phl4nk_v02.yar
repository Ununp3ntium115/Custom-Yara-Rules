rule Linux_Perl_IRCBot_Phl4nk_v02
{
    meta:
        author = "AfterPacket"
        description = "Detects a Perl-based IRC bot (Phl4nk PerlBot v.02) recovered during an active SSH intrusion"
        date = "2026-08-03"

        yarahub_author_email = "jordan@lassiter.eu"
        yarahub_reference_link = "https://github.com/AfterPacket/Drosera"
        yarahub_reference_md5 = "4c78efb135174df31abadaa95c43d470"
        yarahub_uuid = "212c11a8-2be9-4326-9720-2422712d89c2"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

        family = "Perl IRC Bot"
        platform = "Linux"
        malware_type = "IRC Bot"
        sha256 = "03a4f492af99d2048f713081560b8fa45312e594e8439eefa714f0c67a1e0550"

    strings:
        $family1 = "Phl4nk PerlBot" ascii nocase
        $family2 = "Bot Modder : phl4nk" ascii nocase
        $family3 = "Bot Version : v.02" ascii
        $family4 = "Bot Year : 2016" ascii
        $channel = "#mot" ascii
        $operator = "MAD" ascii
        $join = "A Zombie has risen to join the hoard" ascii
        $ua = "get-minimal/20000118" ascii
        $perl1 = "IO::Socket::INET" ascii
        $perl2 = "IO::Select" ascii
        $perl3 = "/usr/bin/perl" ascii
        $scan = "Portscan" ascii nocase
        $udp = "UDP Flood" ascii nocase
        $tcp = "TCP Flood" ascii nocase
        $http = "HTTP Flood" ascii nocase
        $shell = "Back Connect" ascii nocase
        $proc1 = "/usr/sbin/httpd" ascii
        $proc2 = "/usr/sbin/apache2" ascii
        $proc3 = "/usr/sbin/sshd" ascii
        $proc4 = "/sbin/syslogd" ascii

    condition:
        filesize < 100KB and
        $perl1 and
        $perl2 and
        (
            (2 of ($family*)) or
            ($channel and $operator and $join) or
            ($ua and 2 of ($scan,$udp,$tcp,$http,$shell)) or
            (3 of ($proc*))
        )
}
