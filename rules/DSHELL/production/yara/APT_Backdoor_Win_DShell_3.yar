// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_DShell_3
{
    meta:
        description = "This rule looks for strings specific to the D programming language in combination with sections of an integer array which contains the encoded payload found within DShell"
        md5 = "cf752e9cd2eccbda5b8e4c29ab5554b6"
        rev = 3
        author = "FireEye"
    strings:
        $dlang1 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\utf.d" ascii wide
        $dlang2 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\file.d" ascii wide
        $dlang3 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\format.d" ascii wide
        $dlang4 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\base64.d" ascii wide
        $dlang5 = "C:\\D\\dmd2\\windows\\bin\\..\\..\\src\\phobos\\std\\stdio.d" ascii wide
        $dlang6 = "\\..\\..\\src\\phobos\\std\\utf.d" ascii wide
        $dlang7 = "\\..\\..\\src\\phobos\\std\\file.d" ascii wide
        $dlang8 = "\\..\\..\\src\\phobos\\std\\format.d" ascii wide
        $dlang9 = "\\..\\..\\src\\phobos\\std\\base64.d" ascii wide
        $dlang10 = "\\..\\..\\src\\phobos\\std\\stdio.d" ascii wide
        $dlang11 = "Unexpected '\\n' when converting from type const(char)[] to type int" ascii wide
        $e0 = ",0,"
        $e1 = ",1,"
        $e2 = ",2,"
        $e3 = ",3,"
        $e4 = ",4,"
        $e5 = ",5,"
        $e6 = ",6,"
        $e7 = ",7,"
        $e8 = ",8,"
        $e9 = ",9,"
        $e10 = ",10,"
        $e11 = ",11,"
        $e12 = ",12,"
        $e13 = ",13,"
        $e14 = ",14,"
        $e15 = ",15,"
        $e16 = ",16,"
        $e17 = ",17,"
        $e18 = ",18,"
        $e19 = ",19,"
        $e20 = ",20,"
        $e21 = ",21,"
        $e22 = ",22,"
        $e23 = ",23,"
        $e24 = ",24,"
        $e25 = ",25,"
        $e26 = ",26,"
        $e27 = ",27,"
        $e28 = ",28,"
        $e29 = ",29,"
        $e30 = ",30,"
        $e31 = ",31,"
        $e32 = ",32,"
        $e33 = ",33,"
        $e34 = ",34,"
        $e35 = ",35,"
        $e36 = ",36,"
        $e37 = ",37,"
        $e38 = ",38,"
        $e39 = ",39,"
        $e40 = ",40,"
        $e41 = ",41,"
        $e42 = ",42,"
        $e43 = ",43,"
        $e44 = ",44,"
        $e45 = ",45,"
        $e46 = ",46,"
        $e47 = ",47,"
        $e48 = ",48,"
        $e49 = ",49,"
        $e50 = ",50,"
        $e51 = ",51,"
        $e52 = ",52,"
        $e53 = ",53,"
        $e54 = ",54,"
        $e55 = ",55,"
        $e56 = ",56,"
        $e57 = ",57,"
        $e58 = ",58,"
        $e59 = ",59,"
        $e60 = ",60,"
        $e61 = ",61,"
        $e62 = ",62,"
        $e63 = ",63,"
        $e64 = ",64,"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize > 500KB and filesize < 1500KB and 40 of ($e*) and 1 of ($dlang*)
}