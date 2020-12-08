rule HackTool_MSIL_SharPersist_2
{
    meta:
        md5 = "98ecf58d48a3eae43899b45cec0fc6b7"
        rev = 1
        author = "FireEye"
    strings:
        $a1 = "SharPersist.lib"
        $a2 = "SharPersist.exe"
        $b1 = "ERROR: Invalid hotkey location option given." ascii wide
        $b2 = "ERROR: Invalid hotkey given." ascii wide
        $b3 = "ERROR: Keepass configuration file not found." ascii wide
        $b4 = "ERROR: Keepass configuration file was not found." ascii wide
        $b5 = "ERROR: That value already exists in:" ascii wide
        $b6 = "ERROR: Failed to delete hidden registry key." ascii wide
        $pdb1 = "\\SharPersist\\"
        $pdb2 = "\\SharPersist.pdb"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (@pdb2[1] < @pdb1[1] + 50) or (1 of ($a*) and 2 of ($b*))
}