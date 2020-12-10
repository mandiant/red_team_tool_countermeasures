// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Win_MATRYOSHKA_1
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        description = "matryoshka_process_hollow.rs"
        md5 = "44887551a47ae272d7873a354d24042d"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "ZwQueryInformationProcess" fullword
        $s2 = "WriteProcessMemory" fullword
        $s3 = "CreateProcessW" fullword
        $s4 = "WriteProcessMemory" fullword
        $s5 = "\x00Invalid NT Signature!\x00"
        $s6 = "\x00Error while creating and mapping section. NTStatus: "
        $s7 = "\x00Error no process information - NTSTATUS:"
        $s8 = "\x00Error while erasing pe header. NTStatus: "
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}