rule BOMBA_Roblox_Ultimate_Kill_All
{
    meta:
        author = "GuardDog98"
        description = "BOMBA - Detects all Roblox backdoor logger stealer variants in one rule"
        date = "2026-05-13"
        yarahub_reference_md5 = "1f61403d0609f46cbc7520c20696d025"
        yarahub_uuid = "6fa3ea5c-806e-4d8e-a733-da8e468972a7"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_link = "https://github.com/GuardDog98"

    strings:
        $wh1 = "rbxhook" ascii nocase
        $wh2 = "discord.com/api/webhooks" ascii nocase
        $wh3 = "discordapp.com/api/webhooks" ascii nocase
        $wh4 = "webhook" ascii nocase
        $wh5 = "lewisakura" ascii nocase
        $steal1 = ".ROBLOSECURITY" ascii nocase
        $steal2 = "ROBLOSECURITY" ascii nocase
        $steal3 = "ip-api.com" ascii nocase
        $steal4 = "api.ipify.org" ascii nocase
        $load1 = "loadstring" ascii nocase
        $load2 = "HttpGet" ascii nocase
        $load3 = "HttpPost" ascii nocase
        $load4 = "request(" ascii nocase
        $load5 = "syn.request" ascii nocase
        $load6 = "http_request" ascii nocase
        $obf1 = "string.char" ascii nocase
        $obf2 = "string.byte" ascii nocase
        $obf3 = "\\x" ascii nocase
        $obf4 = "getfenv" ascii nocase
        $obf5 = "setfenv" ascii nocase
        $obf6 = "getgenv" ascii nocase
        $admin1 = "devNames" ascii nocase
        $admin2 = "/bring" ascii nocase
        $admin3 = "/kill all" ascii nocase
        $admin4 = "/freeze" ascii nocase
        $admin5 = ":tm" ascii nocase

    condition:
        uint16(0) != 0x4D5A and filesize < 2MB and ((2 of ($wh*) and 1 of ($steal*) and 1 of ($load*)) or (1 of ($wh*) and 1 of ($load*) and 2 of ($obf*)) or (1 of ($admin*) and 2 of ($load*)) or (1 of ($load*) and 3 of ($obf*)))
}
