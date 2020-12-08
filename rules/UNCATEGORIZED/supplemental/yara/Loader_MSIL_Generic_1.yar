rule Loader_MSIL_Generic_1
{
    meta:
        md5 = "b8415b4056c10c15da5bba4826a44ffd"
        rev = 5
        author = "FireEye"
    strings:
        $MSIL = "_CorExeMain"
        $opc1 = { 00 72 [4] 0A 72 [4] 0B 06 28 [4] 0C 12 03 FE 15 [4] 12 04 FE 15 [4] 07 14 }
        $str1 = "DllImportAttribute"
        $str2 = "FromBase64String"
        $str3 = "ResumeThread"
        $str4 = "OpenThread"
        $str5 = "SuspendThread"
        $str6 = "QueueUserAPC"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and $MSIL and all of them
}