// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_HackTool_MSIL_ADPassHunt_2
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "LDAP://" wide
        $s2 = "[GPP] Searching for passwords now..." wide
        $s3 = "Searching Group Policy Preferences (Get-GPPPasswords + Get-GPPAutologons)!" wide
        $s4 = "possibilities so far)..." wide
        $s5 = "\\groups.xml" wide
        $s6 = "Found interesting file:" wide
        $s7 = "\x00GetDirectories\x00"
        $s8 = "\x00DirectoryInfo\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}