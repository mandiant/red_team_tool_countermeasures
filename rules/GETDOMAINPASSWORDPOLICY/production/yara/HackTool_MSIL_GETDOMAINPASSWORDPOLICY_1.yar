rule HackTool_MSIL_GETDOMAINPASSWORDPOLICY_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the recon utility 'getdomainpasswordpolicy' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 4
        author = "FireEye"
    strings:
        $typelibguid0 = "a5da1897-29aa-45f4-a924-561804276f08" ascii nocase wide
    condition:
        filesize < 10MB and (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}