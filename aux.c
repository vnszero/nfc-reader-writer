#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(){
    uint8_t value = 0x00;
    for (int i=0; i<64; i++) {
        printf("%02hhX\n", value);
        value++;
    }
}