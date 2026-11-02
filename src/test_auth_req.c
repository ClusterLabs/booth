#include <stdio.h>
#include <string.h>

#include "inline-fn.h"

int main(void)
{
	struct booth_config conf;

	memset(&conf, 0, sizeof(conf));
	conf.authkey_len = 64;
	if (!is_auth_req(&conf)) {
		fprintf(stderr, "NUL-first binary key should enable authentication\n");
		return 1;
	}

	conf.authkey[0] = 'A';
	if (!is_auth_req(&conf)) {
		fprintf(stderr, "non-NUL key should enable authentication\n");
		return 2;
	}

	conf.authkey_len = 0;
	if (is_auth_req(&conf)) {
		fprintf(stderr, "empty key should not enable authentication\n");
		return 3;
	}

	if (is_auth_req(NULL)) {
		fprintf(stderr, "missing config should not enable authentication\n");
		return 4;
	}

	return 0;
}
