rule SUSP_Bincrypter_Decrypt_Hook
{
    meta:
        description = "bincrypter decryption hook (decoded stage 2 or unobfuscated build)"
        reference = "https://github.com/hackerschoice/bincrypter"
        author = "Peter Gabaldon"
        date = "2026-08-23"
        severity = "medium"
        yarahub_reference_link = "https://gist.github.com/PeterGabaldon/e5b9a6c4ad4e3278481fb5cb02d67a8c"
        yarahub_reference_md5 = "9f81e196548efc844bd8c407a0be834c"
        yarahub_uuid = "07b8dd14-e6c0-48bd-a3f9-8cfcf9aa0ef5"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $esc = "s/B3/\\n/g"
        $esc2 = "s/B1/"
        $esc3 = "s/B2/B/g"
        $enc = "s/B/B2/g"
        $aes = "openssl enc -d -aes-256-cbc -md sha256 -nosalt -k"
        $fn = "_bc_dec"
        $err = "BC_FN=FileName source FileName"

    condition:
        filesize < 10 MB
        and ( ( $esc and $esc2 and $esc3 ) or $enc )
        and 1 of ($aes, $fn, $err)
}
