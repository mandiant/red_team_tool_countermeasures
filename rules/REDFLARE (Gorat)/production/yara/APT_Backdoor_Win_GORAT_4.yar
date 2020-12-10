// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_GORAT_4
{
    meta:
        description = "Verifies that the sample is a Windows PE that is less than 10MB in size and exports numerous functions that are known to be exported by the Gorat implant. This is done in an effort to provide detection for packed samples that may not have other strings but will need to replicate exports to maintain functionality."
        md5 = "f59095f0ab15f26a1ead7eed8cdb4902"
        rev = 8
        author = "FireEye"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10MB and pe.exports("MemoryCallEntryPoint") and pe.exports("MemoryDefaultAlloc") and pe.exports("MemoryDefaultFree") and pe.exports("MemoryDefaultFreeLibrary") and pe.exports("MemoryDefaultGetProcAddress") and pe.exports("MemoryDefaultLoadLibrary") and pe.exports("MemoryFindResource") and pe.exports("MemoryFindResourceEx") and pe.exports("MemoryFreeLibrary") and pe.exports("MemoryGetProcAddress") and pe.exports("MemoryLoadLibrary") and pe.exports("MemoryLoadLibraryEx") and pe.exports("MemoryLoadResource") and pe.exports("MemoryLoadString") and pe.exports("MemoryLoadStringEx") and pe.exports("MemorySizeofResource") and pe.exports("callback") and pe.exports("crosscall2") and pe.exports("crosscall_386")
}