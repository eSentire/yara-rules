rule Prometei
{
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/tenant-from-hell-prometeis-unauthorized-stay-in-your-windows-server"

    strings:

        $xor_key_dll = { 
            C6 80 [4] 5C 
            C6 80 [4] 6D 
            C6 80 [4] 73 
            C6 80 [4] 68 
            C6 80 [4] 6C 
            C6 80 [4] 70 
            C6 80 [4] 64 
            C6 80 [4] 61 
        }

        $decrypt = { BF ?? ?? ?? ?? 8A 4D ?? 02 C8 30 0F }

        $bogus_log = { 
            C6 05 [4] 73 
            C6 05 [4] 65 
            C6 05 [4] 74 
            C6 05 [4] 75 
            C6 05 [4] 70 
            C6 05 [4] 5F 
            C6 05 [4] 67 
            C6 05 [4] 69 
        }

        $systeminfo = { C6 05 [4] 73
            C6 05 [4] 79
            C6 05 [4] 73
            C6 05 [4] 74
            C6 05 [4] 65
            C6 05 [4] 6D
            C6 05 [4] 69
            C6 05 [4] 6E
            C6 05 [4] 66
            C6 05 [4] 6F
        }

        $cpuid = { 
            0D 00 00 20 00 
            50 
            9D 
            9C 
            58 
            25 00 00 20 00 
            3D 00 00 20 00 
            74 
        }

        $rdtsc = { 
            F6 45 ?? 10 
            59 
            59 
            5F 
            74 ?? 
            0F 31 
            C9 
            C3 
        }

    condition:
        3 of them

}
