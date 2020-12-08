rule Trojan_Macro_RESUMEPLEASE_1
{
    meta:
        date_created = "2020-12-01"
        date_modified = "2020-12-01"
        md5 = "d5d3d23c8573d999f1c48d3e211b1066"
        rev = 1
        author = "FireEye"
    strings:
        $str00 = "For Binary As"
        $str01 = "Range.Text"
        $str02 = "Environ("
        $str03 = "CByte("
        $str04 = ".SpawnInstance_"
        $str05 = ".Create("
    condition:
        all of them
}