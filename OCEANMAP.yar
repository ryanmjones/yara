rule OCEANMAP

{

    meta:

        description = "looking for possible OCEANMAP binaries"

        author = "rjones"

        date = "2024-03-03"

        source = "
https://cert.gov.ua/article/6276894
"

        yarahub_reference_sha256 = "
24fd571600dcc00bf2bb8577c7e4fd67275f7d19d852b909395bebcbb1274e04
"

        yarahub_reference_md5 = "
5db75e816b4cef5cc457f0c9e3fc4100
"

        yarahub_uuid = "a99d3eae-5767-438e-96ce-f8418e57e5d0"

        yarahub_license = "CC BY-NC-SA 4.0"

        yarahub_rule_matching_tlp = "TLP:GREEN"

        yarahub_rule_sharing_tlp = "TLP:GREEN"

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
