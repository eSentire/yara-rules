rule Amatera_Stealer
{
    meta:
        author      = "YungBinary"
        description = "Amatera Stealer: XXTEA + DJB2, FreshyCalls syscall resolver, Wow64 syscall stub, UA geofence, Kaspersky drivers"

    strings:

        $crypto_xxtea_delta = { C7 44 24 04 00 00 37 9E C7 04 24 B9 79 00 00 }
        $crypto_djb2 = { 89 D7 C1 E7 05 01 D7 0F B6 D1 01 FA 8A 0E 46 }
        $resolver_wow64_xorSSN = { A1 ?? ?? ?? ?? 35 ?? ?? ?? ?? 8B D4 64 FF 15 C0 00 00 00 C3 }
        $resolver_scan_B8 = { 80 7C 19 FE B8 74 ?? 43 83 FB 22 75 }
        $resolver_hook_range = { 89 0C 24 81 C1 17 FF FF FF 83 F9 16 77 }
        $resolver_hook_bittest = { 8B 0C 24 81 C1 17 FF FF FF 0F A3 CE 72 }
        $resolver_nt_filter = { 80 ?? ?? 4E 75 ?? 80 ?? ?? ?? 64 8B }
        $antidebug_peb = { 80 7? 02 00 75 ?? F6 ?? 68 70 74 }
        $geofence_UA_keyboard = { BA FF 03 00 00 8B 74 8C ?? 21 D6 83 FE 22 0F 94 C3 0F }

        $kaspersky_klif   = "\\??\\C:\\Windows\\System32\\drivers\\klif.sys"   ascii
        $kaspersky_kldisk = "\\??\\C:\\Windows\\System32\\drivers\\kldisk.sys" ascii
        $kaspersky_klhk   = "\\??\\C:\\Windows\\System32\\drivers\\klhk.sys"   ascii
        $kaspersky_kneps  = "\\??\\C:\\Windows\\System32\\drivers\\kneps.sys"  ascii

    condition:
        filesize < 400KB
        and (
            3 of ($resolver_*)
            or ( $resolver_wow64_xorSSN and 2 of ($crypto_*, $antidebug_peb, $geofence_UA_keyboard) )
            or all of ($kaspersky_*)
        )
}
