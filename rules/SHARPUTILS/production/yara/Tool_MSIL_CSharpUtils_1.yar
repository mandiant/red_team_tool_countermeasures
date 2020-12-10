// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Tool_MSIL_CSharpUtils_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'CSharpUtils' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        rev = 1
        author = "FireEye"
    strings:
        $typelibguid0 = "2130bcd9-7dd8-4565-8414-323ec533448d" ascii nocase wide
        $typelibguid1 = "319228f0-2c55-4ce1-ae87-9e21d7db1e40" ascii nocase wide
        $typelibguid2 = "4471fef9-84f5-4ddd-bc0c-31f2f3e0db9e" ascii nocase wide
        $typelibguid3 = "5c3bf9db-1167-4ef7-b04c-1d90a094f5c3" ascii nocase wide
        $typelibguid4 = "ea383a0f-81d5-4fa8-8c57-a950da17e031" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}