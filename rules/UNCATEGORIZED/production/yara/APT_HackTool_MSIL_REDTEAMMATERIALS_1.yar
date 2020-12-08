rule APT_HackTool_MSIL_REDTEAMMATERIALS_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'red_team_materials' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "86c95a99-a2d6-4ebe-ad5f-9885b06eab12" ascii nocase wide
        $typelibguid1 = "e06f1411-c7f8-4538-bbb9-46c928732245" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}