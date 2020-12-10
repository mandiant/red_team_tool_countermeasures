// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_MacOS_GORAT_1
{
    meta:
        description = "This rule is looking for specific strings associated with network activity found within the MacOS generated variant of GORAT"
        md5 = "68acf11f5e456744262ff31beae58526"
        rev = 3
        author = "FireEye"
    strings:
        $s1 = "SID1=%s" ascii wide
        $s2 = "http/http.dylib" ascii wide
        $s3 = "Mozilla/" ascii wide
        $s4 = "User-Agent" ascii wide
        $s5 = "Cookie" ascii wide
    condition:
        ((uint32(0) == 0xBEBAFECA) or (uint32(0) == 0xFEEDFACE) or (uint32(0) == 0xFEEDFACF) or (uint32(0) == 0xCEFAEDFE)) and all of them
}