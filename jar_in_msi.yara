rule jar_in_msi
{
    meta:
        description = "Detect jar appended to MSI"
        author = "Securityinbits"
        date = "2020-06-14"
        reference = "https://twitter.com/Securityinbits/status/1271406138588708866"
        hash_1 = "13a4072d8d0eba59712bb4ec251e0593"
        hash_2 = "63bed40e369b76379b47818ba912ee43"
        hash_3 = "85eb931d0d27179ae7c13085fb050b11"

    strings:
        $msi_magic = { D0 CF 11 E0 A1 B1 1A E1}

        //To detect zip Local file header(lfh) & End of central directory record(eocd)
        $s_zip_magic_lfh = {50 4B 03 04}
        $s_zip_magic_eocd = {50 4B 05 06}

        $s_jar = "META-INF/MANIFEST.MF"
        $s_java_class = ".class"

    condition:
        $msi_magic at 0 and filesize > 200KB and all of ($s_*) 
}
