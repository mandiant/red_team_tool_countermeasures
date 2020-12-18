// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"
rule Loader_MSIL_DUEDLLIGENCE_3
{
    meta:
        author = "FireEye"
    strings:
        $create_thread_injected = { 7E [2] 00 0A 0A 16 0B 16 8D [2] 00 01 0C 28 [2] 00 06 2? ?? 2A 28 [2] 00 0A 1E 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 0C 7E [2] 00 0A 08 8E 69 7E [2] 00 04 7E [2] 00 04 28 [2] 00 06 0D 09 7E [2] 00 0A 28 [2] 00 0A }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
        $rc4 = { 20 00 01 00 00 8D [2] 00 01 1? ?? 20 00 01 00 00 8D [2] 00 01 1? ?? 03 8E 69 8D [2] 00 01 1? ?? 16 0B 2B ?? 1? ?? 07 02 07 02 8E 69 5D 91 9E 1? ?? 07 07 9E 07 17 58 0B 07 20 00 01 00 00 32 }
        $suspended_process = { 12 ?? FE 15 [2] 00 02 1? ?? FE 15 [2] 00 02 02 14 7E [2] 00 0A 7E [2] 00 0A 16 20 [2] 00 08 7E [2] 00 0A 14 12 ?? 12 ?? 28 [2] 00 06 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}