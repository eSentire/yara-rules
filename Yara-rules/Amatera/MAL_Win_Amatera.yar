import "pe"

rule MAL_Win_Amatera_Config_Mem
{
    meta:
        author = "eSentire Threat Response Unit (TRU) | @jgajek"
        description = "https://www.esentire.com/blog/amatera-stealer-4-0-2-beta-whats-new-in-this-variant"

    strings:
        /* Includes the NUL terminator used as the tenth key byte. */
        $family_config_key = { 38 35 32 31 34 39 37 32 33 00 }
        $legacy_config_uuid = "f1575b64-8492-4e8b-b102-4d26e8c70371" ascii

        $artifact_abe = "app_bound_encrypted_key" ascii wide
        $artifact_chromium_ext = "Local Extension Settings" ascii wide
        $artifact_firefox_ext = "extensions.webextensions.uuids" ascii wide
        $artifact_steam_users = "loginusers.vdf" ascii wide
        $artifact_steam_store = "MachineUserConfigStore" ascii wide
        $artifact_powershell = "-NoProfile -NonInteractive -ExecutionPolicy Bypass" ascii wide
        $artifact_module_rundll = "rundll32.exe" ascii wide
        $artifact_module_msi = "/qn /norestart" ascii wide
        $artifact_dns_message = "application/dns-message" ascii wide

    condition:
        $family_config_key
        and (
            $legacy_config_uuid
            or 2 of ($artifact_*)
        )
}


rule MAL_Win_Amatera_Legacy_Static_Config
{
    meta:
        author = "eSentire Threat Response Unit (TRU) | @jgajek"
        description = "https://www.esentire.com/blog/amatera-stealer-4-0-2-beta-whats-new-in-this-variant"

    strings:
        $family_config_key = { 38 35 32 31 34 39 37 32 33 00 }
        $legacy_config_uuid = "f1575b64-8492-4e8b-b102-4d26e8c70371" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.is_32bit()
        and all of them
}


rule MAL_Win_Amatera_ACR_NTSockets_WoW64
{
    meta:
        author = "eSentire Threat Response Unit (TRU) | @jgajek"
        description = "https://www.esentire.com/blog/amatera-stealer-4-0-2-beta-whats-new-in-this-variant"

    strings:
        /*
            AFD_BIND (0x12003) followed by AFD_CONNECT (0x12007).
            Relative calls and branch distances are wildcarded.
        */
        $afd_bind_connect = {
            6A 00 6A 14 50 68 03 20 01 00
            E8 ?? ?? ?? ?? 84 C0 74 ??
            [10-40]
            6A 00 6A 1C 50 68 07 20 01 00
            E8 ?? ?? ?? ?? 84 C0
        }

        /* AFD_SEND (0x1201F). */
        $afd_send = {
            52 6A 10 50 68 1F 20 01 00
            E8 ?? ?? ?? ?? 84 C0
        }

        /* AFD_RECV (0x12017). */
        $afd_recv = {
            50 6A 10 8D 44 24 ?? 50 68 17 20 01 00
            E8 ?? ?? ?? ?? 84 C0
        }

        /*
            Heaven's Gate sequence used by the analyzed branch:
            CS 0x33 -> GS:[0x30] -> WOW64 TEB32/PEB32 -> CS 0x23.
        */
        $wow64_heavens_gate_peb = {
            A1 ?? ?? ?? ?? 85 C0 75 ??
            6A 33 E8 00 00 00 00 83 04 24 05 CB
            65 48 8B 04 25 30 00 00 00
            48 05 00 20 00 00 8B 40 30
            E8 00 00 00 00 C7 44 24 04 23 00 00 00
            83 04 24 0D CB
        }

        /* XOR-decoded SSN followed by WoW64Transition through FS:[0xC0]. */
        $wow64_recycledgate = {
            A1 ?? ?? ?? ?? 35 ?? ?? ?? ??
            8B D4 64 FF 15 C0 00 00 00 C3
        }

    condition:
        uint16(0) == 0x5A4D
        and pe.is_32bit()
        and 2 of ($afd_*)
        and 1 of ($wow64_*)
}


rule MAL_Win_Amatera_4_0_2_RecycledGate_XTEA
{
    meta:
        author = "eSentire Threat Response Unit (TRU) | @jgajek"
        description = "https://www.esentire.com/blog/amatera-stealer-4-0-2-beta-whats-new-in-this-variant"

    strings:
        $crypto_xtea_delta = {
            C7 44 24 04 00 00 37 9E C7 04 24 B9 79 00 00
        }
        $crypto_djb2 = {
            89 D7 C1 E7 05 01 D7 0F B6 D1 01 FA 8A 0E 46
        }

        $resolver_wow64_xor_ssn = {
            A1 ?? ?? ?? ?? 35 ?? ?? ?? ??
            8B D4 64 FF 15 C0 00 00 00 C3
        }
        $resolver_scan_b8 = {
            80 7C 19 FE B8 74 ?? 43 83 FB 22 75
        }
        $resolver_hook_range = {
            89 0C 24 81 C1 17 FF FF FF 83 F9 16 77
        }
        $resolver_hook_bittest = {
            8B 0C 24 81 C1 17 FF FF FF 0F A3 CE 72
        }
        $resolver_nt_filter = {
            80 ?? ?? 4E 75 ?? 80 ?? ?? ?? 64 8B
        }

        $antidebug_peb = {
            80 7? 02 00 75 ?? F6 ?? 68 70 74
        }
        $geofence_ua_keyboard = {
            BA FF 03 00 00 8B 74 8C ?? 21 D6
            83 FE 22 0F 94 C3 0F
        }

    condition:
        uint16(0) == 0x5A4D
        and pe.is_32bit()
        and (
            3 of ($resolver_*)
            or (
                $resolver_wow64_xor_ssn
                and 2 of ($crypto_*, $antidebug_peb, $geofence_ua_keyboard)
            )
        )
}


rule MAL_Win_Amatera_CustomCipher_ConfigBranch
{
    meta:
        author = "eSentire Threat Response Unit (TRU) | @jgajek"
        description = "https://www.esentire.com/blog/amatera-stealer-4-0-2-beta-whats-new-in-this-variant"

    strings:
        /*
            ROR8((cipher XOR key[3]) - key[2], key[1]) XOR key[0].
            Junk instructions between semantic operations are tolerated.
        */
        $byte_transform = {
            0F B6 45 08 32 45 18
            [0-20]
            2A 45 14 8A 4D 10 D2 C8
            [0-20]
            32 45 0C
        }

        /* Repeating-key configuration XOR loop. */
        $config_xor_loop = {
            89 F0 31 D2 F7 F3 8A 04 17
            8B 54 24 ?? 32 04 32 88 04 31 46 EB ??
            C6 04 29 00
        }

        /* Constants from the per-index string keystream generator. */
        $mix_const_1 = { 81 F6 C8 0E 2B EA }
        $mix_const_2 = { B9 95 E9 D1 5B }
        $mix_const_3 = { 69 DB 93 A7 A4 C6 }
        $mix_const_4 = { BA 95 0A 22 27 }
        $mix_const_5 = { 81 F7 E9 E5 43 A7 }
        $mix_const_6 = { BD EB 11 31 13 }
        $mix_const_7 = { BA B9 E5 E4 1C }

    condition:
        uint16(0) == 0x5A4D
        and pe.is_32bit()
        and $byte_transform
        and $config_xor_loop
        and 4 of ($mix_const_*)
}


rule MAL_Win_Amatera_ACR_Family_HighConfidence
{
    meta:
        author = "eSentire Threat Response Unit (TRU) | @jgajek"
        description = "https://www.esentire.com/blog/amatera-stealer-4-0-2-beta-whats-new-in-this-variant"

    condition:
        MAL_Win_Amatera_Legacy_Static_Config
        or MAL_Win_Amatera_4_0_2_RecycledGate_XTEA
        or (
            MAL_Win_Amatera_ACR_NTSockets_WoW64
            and MAL_Win_Amatera_CustomCipher_ConfigBranch
        )
}

