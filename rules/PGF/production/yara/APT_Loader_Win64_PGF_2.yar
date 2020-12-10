// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_PGF_2
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/dllmain/"
        md5 = "4326a7e863928ffbb5f6bdf63bb9126e"
        rev = 2
        author = "FireEye"
    strings:
        $sb1 = { B9 [4] FF 15 [4-32] 8B ?? 1C [0-16] 0F B? ?? 04 [0-64] F3 0F 6F 00 [0-64] 66 0F EF C8 [0-64] F3 0F 7F 08 [0-64] 30 ?? 48 8D 40 01 48 83 ?? 01 7? }
        $sb2 = { 44 8B ?? 08 [0-32] 41 B8 00 30 00 00 [0-16] FF 15 [4-32] 48 8B C8 [0-16] E8 [4-64] 4D 8D 49 01 [0-32] C1 ?? 04 [0-64] 0F B? [2-16] 41 30 ?? FF 45 3? ?? 7? }
        $sb3 = { 63 ?? 3C [0-16] 03 [1-32] 0F B? ?? 14 [0-16] 8D ?? 18 [0-16] 03 [1-16] 66 ?? 3B ?? 06 7? [1-64] 48 8D 15 [4-32] FF 15 [4-16] 85 C0 [2-32] 41 0F B? ?? 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}