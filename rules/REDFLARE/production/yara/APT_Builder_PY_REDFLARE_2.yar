rule APT_Builder_PY_REDFLARE_2
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "4410e95de247d7f1ab649aa640ee86fb"
        rev = 1
        author = "FireEye"
    strings:
        $1 = "<510sxxII"
        $2 = "0x43,0x00,0x3a,0x00,0x5c,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,"
        $3 = "parsePluginOutput"
    condition:
        all of them and #2 == 2
}