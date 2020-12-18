// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"
rule Loader_MSIL_DUEDLLIGENCE_2
{
    meta:
        author = "FireEye"
    strings:
        $1 = "DueDLLigence" fullword
        $2 = "CPlApplet" fullword
        $iz1 = /_Cor(Exe|Dll)Main/ fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}