rule DEVPOPPER
{
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/north-korean-apt-malware-analysis-dev-popper-rat-and-omnistealer-everyday-im-shufflin"
    strings:
        $s1 = "global['_V']" ascii
        $s2 = "typeof module=== 'object'" ascii
        $s3 = "var a0n,a0b,_global,a0a;" ascii
        $s4 = "function(){var rms=''" ascii
        $s5 = "y*(x+360)+(y%32226);" ascii
        $s6 = "wodstriuznuobanchgfcttycmroqrvelspkxj" ascii
    condition:
        filesize < 10KB and (3 of ($s*))
}
