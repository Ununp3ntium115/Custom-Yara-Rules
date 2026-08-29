rule roblox_scam_detector
{
    meta:
        author = "GuardDog98"
        description = "Detects BOMBA Roblox backdoor logger stealer variants. High specificity, low false positives."
        date = "2026-05-16"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_link = "https://github.com/GuardDog98"
        yarahub_reference_md5 = "2121717f8c08dc1f7a07d01740ed416d"
        yarahub_uuid = "7c0a22ff-4555-4df9-9278-50a6c625cd13"

    strings:
        $discord_url_1 = "discord.com/api/webhooks" ascii nocase
        $discord_url_2 = "discordapp.com/api/webhooks" ascii nocase
        $roblox_sec = ".ROBLOSECURITY" ascii nocase
        $roblox_sec_cap = "ROBLOSECURITY" ascii nocase
        $kill_all = "/kill all" ascii nocase
        $freeze_cmd = "/freeze" ascii nocase
        $bring_cmd = "/bring" ascii nocase
        $http_get = "HttpGet" ascii nocase
        $http_post = "HttpPost" ascii nocase
        $syn_request = "syn.request" ascii nocase
        $load_str = "loadstring" ascii nocase
        $lewis_akura = "lewisakura" ascii nocase

    condition:
        uint16(0) != 0x4D5A and
        filesize < 2MB and
        (
            (1 of ($discord_url_1, $discord_url_2) and 1 of ($roblox_sec, $roblox_sec_cap) and 1 of ($http_get, $http_post, $syn_request, $load_str))
            or
            (1 of ($kill_all, $freeze_cmd, $bring_cmd) and 1 of ($roblox_sec, $roblox_sec_cap))
            or
            (1 of ($lewis_akura) and 1 of ($roblox_sec, $roblox_sec_cap) and 1 of ($http_get, $http_post, $syn_request, $load_str))
        )
}
