// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule HackTool_PY_ImpacketObfuscation_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        description = "smbexec"
        md5 = "0b1e512afe24c31531d6db6b47bac8ee"
        rev = 1
        author = "FireEye"
    strings:
        $s1 = "class CMDEXEC" nocase
        $s2 = "class RemoteShell" nocase
        $s3 = "self.services_names"
        $s4 = "import random"
        $s6 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]%CoMSpEC%[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
        $s7 = /self\.__serviceName[\x09\x20]{0,32}=[\x09\x20]{0,32}self\.services_names\[random\.randint\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}len\(self\.services_names\)[\x09\x20]{0,32}-[\x09\x20]{0,32}1\)\]/
    condition:
        all of them
}