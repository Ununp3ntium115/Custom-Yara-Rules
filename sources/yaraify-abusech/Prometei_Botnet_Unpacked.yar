rule Prometei_Botnet_Unpacked
{
    meta:
        description = "Prometei cryptomining botnet (unpacked ELF payload) - SMB-spreading miner with encrypted C2"
        author = "p0tatosmash3r"
        date = "2026-09-05"
        yarahub_author_twitter = ""
        yarahub_reference_link = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.prometei"
        yarahub_reference_md5 = "e7efed36b9ca6a61ed7505aeeec20706"
        yarahub_uuid = "0f9cd6e6-3ad9-4869-a0a9-e3aeecc0771f"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $miner1 = "no active pools, stop mining" ascii
        $smbios1 = "/sys/firmware/dmi/tables/smbios_entry_point" ascii
        $smbios2 = "SMBIOS3" ascii
        $enc1 = "Unable to allocate memory for decrypted struct" ascii
        $enc2 = "Unable to exchange encryption keys" ascii
        $enc3 = "Public key type in decrypted key data not found" ascii
        $ssh = "_libssh2_cipher_crypt" ascii
    condition:
        uint32(0) == 0x464c457f
        and (
            $miner1
            or (2 of ($enc1, $enc2, $enc3))
            or (($smbios1 or $smbios2) and $ssh and 1 of ($enc1, $enc2, $enc3))
        )
}
