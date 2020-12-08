rule Hunting_DotNetToJScript_Functions
{
    meta:
        description = "This file references a selection of functions/classes that are used by the project DotNetToJScript and commonly found in other malware families including GadgetToJScript."
        md5 = "06b6f677d64eef9c4f69ef105b76fba8"
        rev = 1
        author = "FireEye"
    strings:
        $lib1 = "System.Text.ASCIIEncoding"
        $lib2 = "System.Security.Cryptography.FromBase64Transform"
        $lib3 = "System.IO.MemoryStream"
        $lib4 = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"
        $vba1 = "Microsoft.XMLDOM"
        $vba2 = "Microsoft.Windows.ActCtx"
        $vba3 = "System.IO.MemoryStream"
        $vba4 = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"
    condition:
        all of ($lib*) or all of ($vba*)
}