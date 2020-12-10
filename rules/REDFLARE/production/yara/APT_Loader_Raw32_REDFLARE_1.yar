// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Loader_Raw32_REDFLARE_1
{
    meta:
        date_created = "2020-11-27"
        date_modified = "2020-11-27"
        md5 = "4022baddfda3858a57c9cbb0d49f6f86"
        rev = 1
        author = "FireEye"
    strings:
        $load = { EB ?? 58 [0-4] 8B 10 8B 48 [1-3] 8B C8 83 C1 ?? 03 D1 83 E9 [1-3] 83 C1 [1-4] FF D? }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}