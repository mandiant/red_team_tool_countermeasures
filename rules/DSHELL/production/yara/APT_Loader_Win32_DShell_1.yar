// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win32_DShell_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "12c3566761495b8353f67298f15b882c"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $sb2 = { FF 7? 0C B? [4-16] FF 7? 08 5? [0-12] E8 [4] 84 C0 74 05 B? 01 00 00 00 [0-16] 80 F2 01 0F 84 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}