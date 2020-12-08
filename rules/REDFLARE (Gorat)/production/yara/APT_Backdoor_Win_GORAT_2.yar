rule APT_Backdoor_Win_GORAT_2
{
    meta:
        description = "Verifies that the sample is a Windows PE that is less than 10MB in size and has the Go build ID strings. Then checks for various strings known to be in the Gorat implant including strings used in C2 json, names of methods, and the unique string 'murica' used in C2 comms. A check is done to ensure the string 'rat' appears in the binary over 1000 times as it is the name of the project used by the implant and is present well over 2000 times."
        md5 = "f59095f0ab15f26a1ead7eed8cdb4902"
        rev = 7
        author = "FireEye"
    strings:
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
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and all of ($go*) and all of ($json*) and all of ($str*) and #rat > 1000
}