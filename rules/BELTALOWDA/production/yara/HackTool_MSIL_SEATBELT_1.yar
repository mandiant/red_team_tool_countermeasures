rule HackTool_MSIL_SEATBELT_1
{
    meta:
        description = "This rule looks for .NET PE files that have regex and format strings found in the public tool SeatBelt. Due to the nature of the regex and format strings used for detection, this rule should detect custom variants of the SeatBelt project."
        md5 = "848837b83865f3854801be1f25cb9f4d"
        rev = 3
        author = "FireEye"
    strings:
        $msil = "_CorExeMain" ascii wide
        $str1 = "{ Process = {0}, Path = {1}, CommandLine = {2} }" ascii nocase wide
        $str2 = "Domain=\"(.*)\",Name=\"(.*)\"" ascii nocase wide
        $str3 = "LogonId=\"(\\d+)\"" ascii nocase wide
        $str4 = "{0}.{1}.{2}.{3}" ascii nocase wide
        $str5 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii nocase wide
        $str6 = "*[System/EventID={0}]" ascii nocase wide
        $str7 = "*[System[TimeCreated[@SystemTime >= '{" ascii nocase wide
        $str8 = "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?" ascii nocase wide
        $str9 = "{0}" ascii nocase wide
        $str10 = "{0,-23}" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and all of ($str*)
}