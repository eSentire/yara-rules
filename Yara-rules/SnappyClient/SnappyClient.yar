rule SnappyClient {
    meta:
        author = "YungBinary"
        description = "Detects SnappyClient malware"

    strings:
        $config_1 = ",\"kf\":\"" ascii
        $config_2 = "\",\"c\":\"" ascii
        $config_3 = ",\"ab\":\"" ascii
        $config_4 = "{\"tag\":\"" ascii
        $config_5 = "\",\"dd\":\"" ascii
    
        $s1 = "HVncBrowserJob" ascii
        $s2 = "HVncBrowserMigrateJob" ascii
        $s3 = "CBrowserCredentialsJob" ascii
        $s4 = "CSoftwareCredentialsJobMulti" ascii
        $s5 = "CBrowserCredentialsJobMulti" ascii
        $s6 = "KeylogJob" ascii
        $s7 = "FileSearcherJob" ascii
        $s8 = "SoftwareItemEntryJob" ascii
        $s9 = "DownloadJob" ascii
        $s10 = "BrowserEngineType" ascii

    condition:
        all of ($config*) or 4 of ($s*)
}
