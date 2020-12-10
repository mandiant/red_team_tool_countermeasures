// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_MSIL_SharPivot_2
{
    meta:
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        rev = 3
        author = "FireEye"
    strings:
        $s1 = "costura"
        $s2 = "cmd_schtask" wide
        $s3 = "cmd_wmi" wide
        $s4 = "cmd_rpc" wide
        $s5 = "GoogleUpdateTaskMachineUA" wide
        $s6 = "servicehijack" wide
        $s7 = "poisonhandler" wide
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}