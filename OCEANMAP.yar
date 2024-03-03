rule OCEANMAP_hunt
{
    meta:
        description = "looking for possible OCEANMAP binaries"
        author = "rjones"
        source = "https://cert.gov.ua/article/6276894"
        hash = "24fd571600dcc00bf2bb8577c7e4fd67275f7d19d852b909395bebcbb1274e04"
    strings:
        $str1 = "Base64Decode"
        $str2 = "getMessage"
        $str3 = "ReadToEnd"
        $str4 = "get_MachineName"
        $str5 = "get_UserName"
        $str6 = "WriteLine"
        $str7 = "set_UseShellExecute"
        $str8 = "set_ReceiveBufferSize"
        $str9 = "GetCommandLineArgs"
        $str10 = "C:\\WORK\\Source\\tgnews\\tgnews\\obj\\x64\\Release\\VMSearch.pdb"
    condition:
        uint16(0) == 0x5A4D and all of them
}