rule CredTheft_MSIL_ADPassHunt_2
{
    meta:
        md5 = "6efb58cf54d1bb45c057efcfbbd68a93"
        rev = 1
        author = "FireEye"
    strings:
        $pdb1 = "\\ADPassHunt\\"
        $pdb2 = "\\ADPassHunt.pdb"
        $s1 = "Usage: .\\ADPassHunt.exe"
        $s2 = "[ADA] Searching for accounts with msSFU30Password attribute"
        $s3 = "[ADA] Searching for accounts with userpassword attribute"
        $s4 = "[GPP] Searching for passwords now"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@pdb2[1] < @pdb1[1] + 50) or 2 of ($s*)
}