rule DEVPOPPER_INJECTOR
{
    meta:
      author = "YungBinary"
      description = "https://www.esentire.com/blog/north-korean-apt-malware-analysis-dev-popper-rat-and-omnistealer-everyday-im-shufflin"

    strings:
      $marker1 = "/*C250617A*/global" ascii
      $marker2 = "/*C250618A*/global" ascii
      $marker3 = "/*C250619A*/global" ascii

    condition:
      filesize < 700KB and
      (1 of ($marker*))
}
