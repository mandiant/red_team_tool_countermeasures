// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_PRAT_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'prat' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid0 = "7d1219fb-a954-49a7-96c9-df9e6429a8c7" ascii nocase wide
        $typelibguid1 = "bc1157c2-aa6d-46f8-8d73-068fc08a6706" ascii nocase wide
        $typelibguid2 = "c602fae2-b831-41e2-b5f8-d4df6e3255df" ascii nocase wide
        $typelibguid3 = "dfaa0b7d-6184-4a9a-9eeb-c08622d15801" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}