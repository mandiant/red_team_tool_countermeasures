rule Hunting_B64Engine_DotNetToJScript_Dos
{
    meta:
        description = "This file may enclude a Base64 encoded .NET executable. This technique is used by the project DotNetToJScript which is used by many malware families including GadgetToJScript."
        md5 = "7af24305a409a2b8f83ece27bb0f7900"
        rev = 1
        author = "FireEye"
    strings:
        $b64_mz = "AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEU"
    condition:
        $b64_mz
}