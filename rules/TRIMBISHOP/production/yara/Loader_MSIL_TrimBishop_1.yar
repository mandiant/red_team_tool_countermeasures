rule Loader_MSIL_TrimBishop_1
{
    meta:
        description = "This rule looks for .NET PE files that have the string 'msg' more than 60 times as well as numerous function names unique to or used by the TrimBishop tool. All strings found in RuralBishop are reversed in TrimBishop and stored in a variable with the format 'msg##'. With the exception of 'msg', 'DTrim', and 'ReverseString' the other strings referenced in this rule may be shared with RuralBishop."
        md5 = "09bdbad8358b04994e2c04bb26a160ef"
        rev = 3
        author = "FireEye"
    strings:
        $msg = "msg" ascii wide
        $msil = "_CorExeMain" ascii wide
        $str1 = "RuralBishop" ascii wide
        $str2 = "KnightKingside" ascii wide
        $str3 = "ReadShellcode" ascii wide
        $str4 = "ReverseString" ascii wide
        $str5 = "DTrim" ascii wide
        $str6 = "QueensGambit" ascii wide
        $str7 = "Messages" ascii wide
        $str8 = "NtQueueApcThread" ascii wide
        $str9 = "NtAlertResumeThread" ascii wide
        $str10 = "NtQueryInformationThread" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $msil and #msg > 60 and all of ($str*)
}