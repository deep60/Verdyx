rule UPX_Packed_Executable : suspicious
{
    meta:
        author      = "Verdyx"
        description = "Detects UPX compressed executable section headers"
        severity    = "medium"
        category    = "packer"

    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx_sig = { 55 50 58 21 } // UPX!

    condition:
        ($upx0 and $upx1) or $upx_sig
}
