rule CERTUA8399_emails
{
    meta:
        description = "looking for emails from CERT-UA#8399"
        author = "ryanmjones"
        source = "https://cert.gov.ua/article/6276894"
    strings:
        $str1 = {30 4b 48 52 67 74 47 41 30 4c 44 52 67 74 43 31 30 4c 50 52 6c 74 47 58 49 4e 43 6a 30 4c 72 52 67 4e 43 77 30 5a 66 51 76 64 43 34} // "Стратегії України" converted to Base64 then hex
        $str2 = {d0 a1 d1 82 d1 80 d0 b0 d1 82 d0 b5 d0 b3 d1 96 d1 97 20 d0 a3 d0 ba d1 80 d0 b0 d1 97 d0 bd d0 b8 2e 70 64 66 2e 6c 6e 6b} // "Стратегії України.pdf.lnk" converted to hex
        $str3 = {30 4a 72 51 75 4e 47 41 30 4c 6a 51 75 39 43 2b 49 4e 43 53 30 4c 44 51 75 39 43 31 30 4c 33 52 67 74 43 34 30 4c 37 51 73 74 43 34 30 59 63 3d} // "Кирило Валентиович" converted to Base64 then hex
    condition:
        1 of them
}
