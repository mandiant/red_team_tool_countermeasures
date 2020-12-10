// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_5
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "dfbb1b988c239ade4c23856e42d4127b, 3322fba40c4de7e3de0fda1123b0bf5d"
        rev = 3
        author = "FireEye"
    strings:
        $s1 = "AdjustTokenPrivileges" fullword
        $s2 = "LookupPrivilegeValueW" fullword
        $s3 = "ImpersonateLoggedOnUser" fullword
        $s4 = "runCommand" fullword
        $steal_token = { FF 15 [4] 85 C0 [1-40] C7 44 24 ?? 01 00 00 00 [0-20] C7 44 24 ?? 02 00 00 00 [0-20] FF 15 [4] FF [1-5] 85 C0 [4-40] 00 04 00 00 FF 15 [4-5] 85 C0 [2-20] ( BA 0F 00 00 00 | 6A 0F ) [1-4] FF 15 [4] 85 C0 74 [1-20] FF 15 [4] 85 C0 74 [1-20] ( 6A 0B | B9 0B 00 00 00 ) E8 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}