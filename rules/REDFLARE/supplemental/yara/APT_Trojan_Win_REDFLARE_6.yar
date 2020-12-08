rule APT_Trojan_Win_REDFLARE_6
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "294b1e229c3b1efce29b162e7b3be0ab, 6902862bd81da402e7ac70856afbe6a2"
        rev = 2
        author = "FireEye"
    strings:
        $s1 = "RevertToSelf" fullword
        $s2 = "Unsuccessful" fullword
        $s3 = "Successful" fullword
        $s4 = "runCommand" fullword
        $s5 = "initialize" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}