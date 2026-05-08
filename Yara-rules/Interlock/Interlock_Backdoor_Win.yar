rule Interlock_Backdoor_Win
{
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/unmasking-interlock-groups-evolving-malware-arsenal"
    strings:
        $s1 = "{\"iptarget\": \"%d.%d.%d.%d\", \"domain\": \"%s\", \"pcname\": \"%s\", \"user" ascii
    condition:
        $s1
}

