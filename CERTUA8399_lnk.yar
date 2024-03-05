rule CERTUA8399_lnk
{
    meta:
        description = "searching for lnk files related to CERT-UA#8399"
        author = "ryanjones"
        source = "https://cert.gov.ua/article/6276894"
        hash = "593583b312bf48b7748f4372e6f4a560fd38e969399cf2a96798e2594a517bf4"
        hash = "19d0c55ac466e4188c4370e204808ca0bc02bba480ec641da8190cb8aee92bdc"
    strings:
        $str1 = "194.126.178.8/webdav/" ascii wide nocase
        $str2 = "wody.pdf" ascii wide nocase
        $str3 = "python.exe" ascii wide nocase
        $str4 = "Client.py" ascii wide nocase
        $str5 = "powershell.exe" ascii wide nocase
        $str6 = "-w hid -nop  -c" ascii wide nocase
        $str7 = "desktop-q0f4sik" ascii wide nocase
        $str8 = "win-j5ggokh35ap" ascii wide nocase
    condition:
        uint16(0) == 0x004c and 6 of them
}
