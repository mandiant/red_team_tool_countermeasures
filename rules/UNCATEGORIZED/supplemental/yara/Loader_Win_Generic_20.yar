rule Loader_Win_Generic_20
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "5125979110847d35a338caac6bff2aa8"
        rev = 1
        author = "FireEye"
    strings:
        $s0 = { 8B [1-16] 89 [1-16] E8 [4-32] F3 A4 [0-16] 89 [1-8] E8 }
        $s2 = { 83 EC [4-24] 00 10 00 00 [4-24] C7 44 24 ?? ?? 00 00 00 [0-8] FF 15 [4-24] 89 [1-4] 89 [1-4] 89 [1-8] FF 15 [4-16] 3? ?? 7? [4-24] 20 00 00 00 [4-24] FF 15 [4-32] F3 A5 }
        $si1 = "VirtualProtect" fullword
        $si2 = "malloc" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}