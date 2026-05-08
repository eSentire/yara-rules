rule ShadowCoil_Packed_Python
{
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/unpacking-shadowcoils-ransomhub-ex-affiliate-credential-harvesting-tool"
        target_entity = "file"
    strings:
        $a = "exec(pc_start(" ascii
        $b = "get_hw_key():" ascii
        $c = "'vm', 'virtual'" ascii
        $d = "TracerPid:" ascii
    condition:
        all of them
}
