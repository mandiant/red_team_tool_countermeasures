rule Trojan_Raw_Generic_4
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "f41074be5b423afb02a74bc74222e35d"
        rev = 1
        author = "FireEye"
    strings:
        $s0 = { 83 ?? 02 [1-16] 40 [1-16] F3 A4 [1-16] 40 [1-16] E8 [4-32] FF ( D? | 5? | 1? ) }
        $s1 = { 0F B? [1-16] 4D 5A [1-32] 3C [16-64] 50 45 [8-32] C3 }
    condition:
        uint16(0) != 0x5A4D and all of them
}