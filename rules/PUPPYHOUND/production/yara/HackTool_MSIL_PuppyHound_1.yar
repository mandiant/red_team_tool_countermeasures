// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_PuppyHound_1
{
    meta:
        description = "This is a modification of an existing FireEye detection for SharpHound. However, it looks for the string 'PuppyHound' instead of 'SharpHound' as this is all that was needed to detect the PuppyHound variant of SharpHound."
        md5 = "eeedc09570324767a3de8205f66a5295"
        rev = 6
        author = "FireEye"
    strings:
        $1 = "PuppyHound"
        $2 = "UserDomainKey"
        $3 = "LdapBuilder"
        $init = { 28 [2] 00 0A 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 28 [2] 00 0A 0B 1F 2D }
        $msil = /\x00_Cor(Exe|Dll)Main\x00/
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}