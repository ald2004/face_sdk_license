#include "license-decoder.h"


int main(int argc,char** argv)
{
    printf("hello from %s!\n", "boe_facesdk_license");

    if (argc < 2) {
        printf("Usage : license-decoder license_file \n");
        gen_current_hw_finger();
        return 0;
    }
    else {
        
        return decode_lic(argv[1]);
    }
}