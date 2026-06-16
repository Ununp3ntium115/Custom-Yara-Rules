rule tinyload_stub_xxtea
{
    meta:
        description                = "TinyLoad stub: XXTEA delta + phi constant + key XOR masks from dual-thread key recombination"
        author                     = "custom"
        date                       = "2026-06-15"
        reference                  = "https://github.com/iamsopotatoe-coder/TinyLoad"
        yarahub_uuid               = "a1c24f87-3310-4e92-bc01-9f5d7e883a12"
        yarahub_license            = "CC0 1.0"
        yarahub_rule_matching_tlp  = "TLP:WHITE"
        yarahub_rule_sharing_tlp   = "TLP:WHITE"
        yarahub_reference_md5      = "80e06aeeb85ceb944318636d73e24c60"

    strings:
        $xxtea_delta   = { B9 79 37 9E }
        $xxtea_delta64 = { 15 7C 4A 7F B9 79 37 9E }
        $xor_k0        = { 0D F0 ED FE }
        $xor_k1        = { BE BA FE CA }
        $xor_k2        = { EF BE AD DE }
        $xor_k3        = { 0D F0 AD 8B }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 2MB
        and ($xxtea_delta or $xxtea_delta64)
        and 2 of ($xor_k0, $xor_k1, $xor_k2, $xor_k3)
}