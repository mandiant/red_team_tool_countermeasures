rule APT_Backdoor_Win_GORAT_5
{
    meta:
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "cdf58a48757010d9891c62940c439adb, a107850eb20a4bb3cc59dbd6861eaf0f"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "comms.BeaconData" fullword
        $2 = "comms.CommandResponse" fullword
        $3 = "rat.BaseChannel" fullword
        $4 = "rat.Config" fullword
        $5 = "rat.Core" fullword
        $6 = "platforms.AgentPlatform" fullword
        $7 = "GetHostID" fullword
        $8 = "/rat/cmd/gorat_shared/dllmain.go" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
