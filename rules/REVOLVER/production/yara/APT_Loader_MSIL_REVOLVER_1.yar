// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"
rule FE_APT_Loader_MSIL_REVOLVER_1
{
    meta:
        author = "FireEye"
    strings:
        $inject = { 28 [2] 00 06 0? 0? 7B [2] 00 04 7E [2] 00 0A 28 [2] 00 0A [2-40] 7E [2] 00 0A 0? 20 00 10 00 00 28 [2] 00 0A 0? 28 [2] 00 0A 6F [2] 00 0A 1? ?? 7E [2] 00 0A 1? ?? 20 00 30 00 00 1F 40 28 [2] 00 06 [2-40] 28 [2] 00 0A 1? 3? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 1? ?? 1? ?? 1? 0? 1? ?? 8? 6? 28 [2] 00 0A 2? ?? 7E [2] 00 04 7E [2] 00 04 28 [2] 00 0A 28 [2] 00 06 1? ?? 1? ?? 1? 0? 1? ?? 8? 6? 28 [2] 00 0A 1? ?? FE 15 [2] 00 02 1? ?? 72 [2] 00 70 28 [2] 00 06 1? ?? FE 15 [2] 00 02 1? ?? 1? ?? 1? 28 [2] 00 06 2? 7E [2] 00 0A 1? ?? 0? 7B [2] 00 04 1? ?? 1? 1? ?? 28 [2] 00 06 2? ?? 1? ?? 7E [2] 00 0A 28 [2] 00 0A [2-10] 7E [2] 00 0A 1? ?? 1? ?? 20 [2] 1F 00 7E [2] 00 0A 28 [2] 00 0A 6F [2] 00 0A 1? ?? 7E [2] 00 0A 1? 1? 20 [2] 00 00 20 [2] 00 00 7E [2] 00 0A 28 [2] 00 06 2? 1? ?? 7E [2] 00 0A 28 [2] 00 0A [2-40] 1? ?? 0? 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 2? ?? 2? 1? 1? ?? 1? ?? 1? ?? 28 [2] 00 06 }
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}