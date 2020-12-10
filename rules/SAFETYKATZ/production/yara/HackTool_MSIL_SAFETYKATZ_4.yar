// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SAFETYKATZ_4
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public SafetyKatz project."
        md5 = "45736deb14f3a68e88b038183c23e597"
        rev = 3
        author = "FireEye"
    strings:
        $typelibguid1 = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}