rule SUSP_Bincrypter_Shell_Dropper
{
    meta:
        description = "bincrypter-obfuscated shell dropper (THC bincrypter)"
        reference = "https://github.com/hackerschoice/bincrypter"
        author = "Peter Gabaldon"
        date = "2026-08-23"
        severity = "high"
        yarahub_reference_link = "https://gist.github.com/PeterGabaldon/e5b9a6c4ad4e3278481fb5cb02d67a8c"
        yarahub_reference_md5 = "53f5348430a4c30387fa019bc403e2c3"
        yarahub_uuid = "74d36f04-5884-4680-acec-f0a58160529b"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        // _bc_obbell(): empty command substitutions inserted inside keywords.
        $ob_bs  = { 60 21 20 3A 26 26 08 23 60 }
        $ob_bel = { 60 3A 7C 7C 07 60 }

        // Fragments of the loader that survive the insertion.
        $lang = "LANG=C pe"
        $print = ":pr"

    condition:
        uint16(0) == 0x2123 // "#!"
        and filesize > 3 KB
        and ( #ob_bs + #ob_bel ) > 10
        and $lang
        and $print
}
