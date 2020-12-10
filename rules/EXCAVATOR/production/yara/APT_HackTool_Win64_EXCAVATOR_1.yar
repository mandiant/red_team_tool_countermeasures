// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_Win64_EXCAVATOR_1
{
    meta:
        date_created = "2020-11-30"
        date_modified = "2020-11-30"
        md5 = "6a9a114928554c26675884eeb40cc01b"
        rev = 3
        author = "FireEye"
    strings:
        $api1 = "PssCaptureSnapshot" fullword
        $api2 = "MiniDumpWriteDump" fullword
        $dump = { BA FD 03 00 AC [0-8] 41 B8 1F 00 10 00 48 8B ?? FF 15 [4] 85 C0 0F 85 [2] 00 00 [0-2] 48 8D 05 [5] 89 ?? 24 30 ( C7 44 24 28 80 00 00 00 48 8D 0D ?? ?? ?? ?? | 48 8D 0D ?? ?? ?? ?? C7 44 24 28 80 00 00 00 ) 45 33 C9 [0-5] 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 [0-10] FF 15 [4] 48 8B ?? 48 83 F8 FF ( 74 | 0F 84 ) [1-4] 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 30 ( 41 B9 02 00 00 00 | 44 8D 4D 02 ) ?? 89 ?? 24 28 4C 8B ?? 8B [2] 89 ?? 24 20 FF 15 [4] 48 8B ?? FF 15 [4] 48 8B ?? FF 15 [4] FF 15 [4] 48 8B 54 24 ?? 48 8B C8 FF 15 }
        $lsass = { 6C 73 61 73 [6] 73 2E 65 78 [6] 65 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}