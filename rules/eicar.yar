/*
 * Armadillo bundled rules — EICAR antivirus self-test.
 * The EICAR string is the industry-standard, harmless test pattern every AV must
 * detect. It is NOT malware. https://www.eicar.org/download-anti-malware-testfile/
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR Standard Anti-Virus Test File (harmless self-test)"
        family      = "test"
        severity    = "critical"
        reference   = "https://www.eicar.org/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
