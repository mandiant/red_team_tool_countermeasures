// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_MSIL_WILDCHILD_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "6f04a93753ae3ae043203437832363c4"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "\x00QueueUserAPC\x00"
        $s2 = "\x00WriteProcessMemory\x00"
        $sb1 = { 6F [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 13 ?? 28 [2] 00 0A 28 [2] 00 0A 13 ?? 11 ?? 11 ?? 28 [2] 00 0A [0-16] 7B [2] 00 04 1? 20 [4] 28 [2] 00 0A 11 ?? 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 [0-16] 14 7E [2] 00 0A 7E [2] 00 0A 1? 20 04 00 08 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 [0-16] 7B [2] 00 04 7E [2] 00 0A [0-16] 8E ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 [4-120] 28 [2] 00 06 [0-80] 6F [2] 00 0A 6F [2] 00 0A 28 [2] 00 06 13 ?? 11 ?? 11 ?? 7E [2] 00 0A 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}