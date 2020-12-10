// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Hunting_GadgetToJScript_1
{
    meta:
        description = "This rule is looking for B64 offsets of LazyNetToJscriptLoader which is a namespace specific to the internal version of the GadgetToJScript tooling."
        md5 = "7af24305a409a2b8f83ece27bb0f7900"
        rev = 4
        author = "FireEye"
    strings:
        $s1 = "GF6eU5ldFRvSnNjcmlwdExvYWRl"
        $s2 = "henlOZXRUb0pzY3JpcHRMb2Fk"
        $s3 = "YXp5TmV0VG9Kc2NyaXB0TG9hZGV"
    condition:
        any of them
}