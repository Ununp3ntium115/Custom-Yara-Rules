rule SolarisLoader_concatenated_api_dynamic_resolution
{
    meta:
        description               = "Detects SolarisLoader via concatenated API resolution table and hardcoded campaign identifier"
        author                    = "Aldair Maihuiri"
        date                      = "2026-08-08"
        sha256                    = "1fd26ea847d2c3fe431322e42c54fb10024f06e61ce55aa14b162d95bb5bd2d1"
        malware_family            = "SolarisLoader"
        sample_type               = "loader"
        arch                      = "x86-64 PE"
        yarahub_uuid              = "c5d35710-ab0a-4b30-9cc5-afa97365fdbc"
        yarahub_author_twitter    = "@AldairMaihuiri"
        yarahub_reference_link    = "https://ginomaihuiri.github.io"
        yarahub_license           = "CC BY-NC-SA 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_reference_md5     = "3e88f1a1f48cb2a3556fdac9de4e8ef9"

    strings:
        $api_concat = "SHGetFolderPathWNtReadVirtualMem" ascii
        $hex_id = "886ACC7E25406759" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 100KB
        and $api_concat
        and $hex_id
}
