import "dotnet"

rule HUNT_NET_Loader_BitmapStego_LateBindingInvoke
{
    meta:
        author      = "Anish Bogati"
        description = "Hunting: .NET loader reading pixel data from a resource Bitmap, loading an assembly and invoking its first exported method via VB LateBinding"
        date        = "2026-09-26"
        yarahub_uuid = "63128581-e56c-4884-bd5f-b109299f8eac"
        yarahub_reference_md5     = "37d5276210a361c53ad7a6c5252b3f1c"
        yarahub_license           = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
    strings:
        $lb1 = "LateBinding" ascii fullword
        $lb2 = "LateCall" ascii fullword
        $r1  = "GetExportedTypes" ascii fullword
        $r2  = "GetMethods" ascii fullword
        $res = "ComponentResourceManager" ascii fullword
        $px1 = "GetPixel" ascii fullword
        $px2 = "LockBits" ascii fullword
        $inv = "Invoke" wide fullword
    condition:
        dotnet.is_dotnet and
        for any r in dotnet.assembly_refs : ( r.name == "Microsoft.VisualBasic" ) and
        all of ($lb*) and all of ($r*) and $res and $inv and any of ($px*)
}