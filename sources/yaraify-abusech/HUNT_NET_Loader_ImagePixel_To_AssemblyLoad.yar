import "dotnet"

rule HUNT_NET_Loader_ImagePixel_To_AssemblyLoad
{
    meta:
        author      = "Anish Bogati"
        description = "Hunting: .NET loader that reads pixel data from an embedded image, loads it as a .NET assembly, and runs it via reflection or late binding. Catches bitmap-steganography loaders."        
        date        = "2026-09-29"
        yarahub_uuid = "8c39b999-e13a-4507-b89d-1ab5c54438ce"
        yarahub_reference_md5     = "37d5276210a361c53ad7a6c5252b3f1c"
        yarahub_license           = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
    strings:
        // step 1: where the image comes from
        $src1 = "ComponentResourceManager" ascii fullword
        $src2 = "ResourceManager" ascii fullword
        $src3 = "GetManifestResourceStream" ascii fullword
        $src4 = "FromStream" ascii fullword
        // step 2: reading pixels, slow path and fast path
        $gp   = "GetPixel" ascii fullword
        $cr   = "get_R" ascii fullword
        $cg   = "get_G" ascii fullword
        $cb   = "get_B" ascii fullword
        $lk   = "LockBits" ascii fullword
        $scan = "get_Scan0" ascii fullword
        // step 3: loading bytes as code
        $load = "Load" ascii fullword
        // step 4: finding and calling the entry
        $rf1  = "GetExportedTypes" ascii fullword
        $rf2  = "GetTypes" ascii fullword
        $rf3  = "GetMethods" ascii fullword
        $rf4  = "GetMethod" ascii fullword
        $rf5  = "get_EntryPoint" ascii fullword
        $iv1  = "Invoke" ascii fullword
        $iv2  = "Invoke" wide fullword
        $iv3  = "InvokeMember" ascii fullword
        $iv4  = "LateCall" ascii fullword
        $iv5  = "CreateInstance" ascii fullword
    condition:
        dotnet.is_dotnet and filesize < 15MB and
        any of ($src*) and
        (($gp and 2 of ($c*)) or ($lk and $scan)) and
        $load and
        any of ($rf*) and
        any of ($iv*)
}