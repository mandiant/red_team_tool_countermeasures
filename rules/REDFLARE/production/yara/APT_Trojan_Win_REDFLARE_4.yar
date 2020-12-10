// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Trojan_Win_REDFLARE_4
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "a8b5dcfea5e87bf0e95176daa243943d, 9dcb6424662941d746576e62712220aa"
        rev = 2
        author = "FireEye"
    strings:
        $s1 = "LogonUserW" fullword
        $s2 = "ImpersonateLoggedOnUser" fullword
        $s3 = "runCommand" fullword
        $user_logon = { 22 02 00 00 [1-10] 02 02 00 00 [0-4] E8 [4-40] ( 09 00 00 00 [1-10] 03 00 00 00 | 6A 03 6A 09 ) [4-30] FF 15 [4] 85 C0 7? }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}