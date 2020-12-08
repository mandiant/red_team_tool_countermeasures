rule CredTheft_MSIL_TitoSpecial_2
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the TitoSpecial project. There are 2 GUIDs in this rule as the x86 and x64 versions of this tool use a different ProjectGuid."
        md5 = "4bf96a7040a683bd34c618431e571e26"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid1 = "C6D94B4C-B063-4DEB-A83A-397BA08515D3" ascii nocase wide
        $typelibguid2 = "3b5320cf-74c1-494e-b2c8-a94a24380e60" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and ($typelibguid1 or $typelibguid2)
}