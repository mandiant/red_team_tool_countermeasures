rule APT_Backdoor_Win_GORAT_3
{
    meta:
        description = "This rule uses the same logic as FE_APT_Trojan_Win_GORAT_1_FEBeta with the addition of one check, to look for strings that are known to be in the Gorat implant when a certain cleaning script is not run against it."
        md5 = "995120b35db9d2f36d7d0ae0bfc9c10d"
        rev = 5
        author = "FireEye"
    strings:
        $dirty1 = "fireeye" ascii nocase wide
        $dirty2 = "kulinacs" ascii nocase wide
        $dirty3 = "RedFlare" ascii nocase wide
        $dirty4 = "gorat" ascii nocase wide
        $dirty5 = "flare" ascii nocase wide
        $go1 = "go.buildid" ascii wide
        $go2 = "Go build ID:" ascii wide
        $json1 = "json:\"pid\"" ascii wide
        $json2 = "json:\"key\"" ascii wide
        $json3 = "json:\"agent_time\"" ascii wide
        $json4 = "json:\"rid\"" ascii wide
        $json5 = "json:\"ports\"" ascii wide
        $json6 = "json:\"agent_platform\"" ascii wide
        $rat = "rat" ascii wide
        $str1 = "handleCommand" ascii wide
        $str2 = "sendBeacon" ascii wide
        $str3 = "rat.AgentVersion" ascii wide
        $str4 = "rat.Core" ascii wide
        $str5 = "rat/log" ascii wide
        $str6 = "rat/comms" ascii wide
        $str7 = "rat/modules" ascii wide
        $str8 = "murica" ascii wide
        $str9 = "master secret" ascii wide
        $str10 = "TaskID" ascii wide
        $str11 = "rat.New" ascii wide
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and all of ($go*) and all of ($json*) and all of ($str*) and #rat > 1000 and any of ($dirty*)
}