import "math"

rule HKTL_UPX_Packed_Magic_Zeroed
{
    meta:
        description = "UPX-packed ELF64 with the UPX magic zeroed to obstruct unpacking"
        author = "Peter Gabaldon"
        date = "2026-08-23"
        severity = "high"
        note = "Observed in the incident gsocket payload; also detects a generic anti-unpacking technique"
        yarahub_reference_link = "https://gist.github.com/PeterGabaldon/e5b9a6c4ad4e3278481fb5cb02d67a8c"
        yarahub_reference_md5 = "b9744f5ab86676b4a7f53cbb83655081"
        yarahub_uuid = "bbe3cd96-9a27-43bc-a1c1-5e11ad9dcbe7"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $upx = "UPX!"

    condition:
        uint32(0) == 0x464c457f // "\x7fELF"
        and uint8(4) == 2       // ELFCLASS64
        and filesize > 4 KB and filesize < 200 MB

        // l_info = e_phoff + (e_phentsize * e_phnum)
        and uint32(uint32(0x20) + uint16(0x36) * uint16(0x38) + 4) == 0
        and uint32(uint32(0x20) + uint16(0x36) * uint16(0x38)) != 0
        and uint32(uint32(0x20) + uint16(0x36) * uint16(0x38) + 12) == 0
        and uint32(uint32(0x20) + uint16(0x36) * uint16(0x38) + 16) > filesize
        and uint32(uint32(0x20) + uint16(0x36) * uint16(0x38) + 20) > 0
        and (
            uint8(uint32(0x20) + uint16(0x36) * uint16(0x38) + 32) == 2
            or uint8(uint32(0x20) + uint16(0x36) * uint16(0x38) + 32) == 8
            or uint8(uint32(0x20) + uint16(0x36) * uint16(0x38) + 32) == 14
        )
        and uint8(uint32(0x20) + uint16(0x36) * uint16(0x38) + 33) == 0
        and uint32(uint32(0x20) + uint16(0x36) * uint16(0x38) + 24) > 0
        and uint32(uint32(0x20) + uint16(0x36) * uint16(0x38) + 28) > 0

        and not $upx
        // Bound the entropy calculation for predictable global-scan cost.
        and math.entropy(0, math.min(filesize, 1 MB)) > 7.0
}
