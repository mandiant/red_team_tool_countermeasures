rule HackTool_MSIL_PXELOOT_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the PXE And Loot project."
        md5 = "82e33011ac34adfcced6cddc8ea56a81"
        rev = 7
        author = "FireEye"
    strings:
        $typelibguid1 = "78B2197B-2E56-425A-9585-56EDC2C797D6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}