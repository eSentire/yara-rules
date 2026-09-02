import "pe"

rule MAL_Win_Cruciferra_Loader_NativeAOT
{
    meta:
        author = "eSentire Threat Response Unit (TRU) | @jgajek"
        description = "https://www.esentire.com/blog/malware-as-a-service-cocktail-errtraffic-and-cruciferra-killing-your-edr-since-2025"
    strings:
        $a = {
            B8 1D 3C E9 A7
            80 39 00
            74 ??
            48 8D 51 01
            0F B6 09
            33 C1
            C1 C0 0D
            69 C0 A9 D2 B7 C5
            8B C8
            C1 E9 0F
            33 C1
            80 3A 00
            48 8B CA
            75 ??
            C3
        }

        /* Independent NativeAOT runtime markers present in all known builds. */
        $aot_rehydrate = "RehydrateData" ascii
        $aot_rtr_type  = "ReadyToRunSectionType" ascii
        $aot_rhp       = "RhpCidResolve" ascii
        $aot_gc        = ".NET BGC" ascii

    condition:
        uint16(0) == 0x5a4d and
        pe.machine == pe.MACHINE_AMD64 and
        pe.is_dll() and
        $a and
        2 of ($aot_*)
}

