rule APT_Loader_MSIL_PGF_2
{
    meta:
        date_created = "2020-11-25"
        date_modified = "2020-11-25"
        description = "base.js, ./lib/payload/techniques/jscriptdotnet/jscriptdotnet_payload.py"
        md5 = "7c2a06ceb29cdb25f24c06f2a8892fba"
        rev = 1
        author = "FireEye"
    strings:
        $sb1 = { 2? 00 10 00 00 0A 1? 40 0? 72 [4] 0? 0? 28 [2] 00 0A 0? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 0? 74 [2] 00 01 28 [2] 00 0A 6? 0? 0? 28 [2] 00 06 D0 [2] 00 01 28 [2] 00 0A 1? 28 [2] 00 0A 79 [2] 00 01 71 [2] 00 01 13 ?? 0? 1? 11 ?? 0? 74 [2] 00 01 28 [2] 00 0A 28 [2] 00 0A 7E [2] 00 0A 13 ?? 1? 13 ?? 7E [2] 00 0A 13 ?? 03 28 [2] 00 0A 74 [2] 00 01 6F [2] 00 0A 03 1? 1? 11 ?? 11 ?? 1? 11 ?? 28 [2] 00 06 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "\x00ScriptObjectStackTop\x00"
        $ss3 = "\x00Microsoft.JScript\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}