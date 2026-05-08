rule Amatera_Shellcode_Loader
{
    meta:
        author      = "YungBinary"
        description = "Amatera Stealer shellcode loader"

    strings:
        $peb_from_teb = { 64 A1 18 00 00 00 8B 40 30 }
        $peb_ldr_inload = { 8B 48 0C 83 C1 0C }
        $os_pre_win81_gate = {
            64 8B 0D 18 00 00 00
            8B 49 30
            8B 91 A4 00 00 00
            C1 E2 08
            66 0B 91 A8 00 00 00
            66 81 FA 03 06
            72
        }
        $pe_erase_flag = { 8A 85 88 00 00 00 88 44 24 }
        $hash_lowercase_mul31 = { 0F B6 37 6B D2 1F 47 83 CE 20 }
        $loop_memcpy_off89 = { 8A 8C 05 89 00 00 00 88 0C 03 40 EB }
        $loop_xor_decrypt = { 8A 4C 0D 08 30 0C 03 40 EB }

    condition:
        filesize < 3MB and 4 of them
}