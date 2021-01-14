#include <stdio.h>
#include "rc4.h"


int main(int argc, char *argv[]) {

	struct rc4_state state;
	unsigned char key[6] = {0x23, 0x24, 0x12, 0x34, 0x11, 0x12};
	unsigned char out1[] = "coucou";
	unsigned char out2[256];
	unsigned char out3[256];
	int i = 0;

	rc4_init(&state, key, 6);

	rc4_crypt(&state, out1, out2, 6);

	for (i = 0; i < 6; i ++) {
		printf("%0x ", out1[i]);
	}
	printf("\n");

	for (i = 0; i < 6; i ++) {
                printf("%0x ", out2[i]);
        }
        printf("\n");

	rc4_init(&state, key, 6);
	rc4_crypt(&state, out2, out3, 6);

	for (i = 0; i < 6; i ++) {

		printf("%0x ", out3[i]);
	}
	printf("\n");

	return 0;
}

