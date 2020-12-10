// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win64_PGF_1
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base dlls: /lib/payload/techniques/unmanaged_exports/"
        md5 = "2b686a8b83f8e1d8b455976ae70dab6e"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { B9 14 00 00 00 FF 15 [4-32] 0F B6 ?? 04 [0-32] F3 A4 [0-64] 0F B6 [2-3] 0F B6 [2-3] 33 [0-32] 88 [1-9] EB }
        $sb2 = { 41 B8 00 30 00 00 [0-32] FF 15 [8-64] 83 ?? 01 [4-80] 0F B6 [1-64] 33 [1-32] 88 [1-64] FF ( D? | 5? ) }
        $sb3 = { 48 89 4C 24 08 [4-64] 48 63 48 3C [0-32] 48 03 C1 [0-64] 0F B7 48 14 [0-64] 48 8D 44 08 18 [8-64] 0F B7 40 06 [2-32] 48 6B C0 28 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}