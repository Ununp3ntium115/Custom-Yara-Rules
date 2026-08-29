rule Hunt_LNK_EpochTimestamp_StrippedMetadata {
    meta:
        description = "Detects LNK files with timestamps reset to Jan 1, 1970 and stripped MAC/NetBIOS metadata"
        author = "Serhii Kocherhan"
        date = "2026-08-17"
        yarahub_uuid = "5a26e50e-55a7-4544-bef4-bbe3c538f8db"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "00000000000000000000000000000000"

    strings:
        // LNK Header Magic Number: 0x00021401
        $lnk_header = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }

        // FILETIME structure for 1970-01-01 00:00:00 UTC (0x019DB1DED53E8000 in Little Endian)
        $ft_1970 = { 00 80 3E D5 DE B1 9D 01 }

        // Zeroed 6-byte MAC address pattern inside a GUID/UUID (Version 1 UUID node field)
        $zero_mac = { 00 00 00 00 00 00 }

    condition:
        // Validate LNK Header
        $lnk_header at 0 and

        // Check for 1970 FILETIME at CreationTime (offset 0x1C), AccessTime (0x24), or WriteTime (0x2C)
        (
            uint64(0x1C) == 0x019DB1DED53E8000 or
            uint64(0x24) == 0x019DB1DED53E8000 or
            uint64(0x2C) == 0x019DB1DED53E8000
        ) and

        // Check for stripped MAC or NetBIOS metadata block
        (
            $zero_mac or
            // Search for empty/padded LinkTracker or TrackerDataBlock structures
            uint32be(filesize - 4) == 0x00000000
        )
}