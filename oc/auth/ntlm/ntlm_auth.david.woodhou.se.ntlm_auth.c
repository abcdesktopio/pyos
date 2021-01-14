/* Build with:
  gcc -o ntlm_auth ntlm_auth.c -DPASSWORD=pwd -DUSERNAME=who -DDOMAIN=which `pkg-config --cflags --libs glib-2.0 libntlm`
 */


#include <ntlm.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#if !defined(USERNAME) || !defined(DOMAIN) || !defined(PASSWORD)
#error Must be built with USERNAME, DOMAIN and PASSWORD defined
#endif

#define __STRINGIFY(x) #x
#define STRINGIFY(x) __STRINGIFY(x)

const char username[] = STRINGIFY(USERNAME);
const char password[] = STRINGIFY(PASSWORD);
const char domain[] = STRINGIFY(DOMAIN);

int main(void)
{
	char buf[1024];

	while (fgets(buf, 1024, stdin)) {
		if (buf[0] == 'Y' && buf[1] == 'R') {
			tSmbNtlmAuthRequest rq;
			char *outstr;
			buildSmbNtlmAuthRequest_noatsplit(&rq, username, domain);
			outstr = g_base64_encode((void *)&rq, SmbLength(&rq));
			printf("YR %s\n", outstr);
			fflush(stdout);
			g_free(outstr);
		} else if (buf[0] == 'T' && buf[1] == 'T' && buf[2] == ' ') {
			tSmbNtlmAuthChallenge *chl;
			tSmbNtlmAuthResponse rsp;
			size_t size;
			gchar *outstr;

			chl = (void *)g_base64_decode(buf+3, &size);
			buildSmbNtlmAuthResponse_noatsplit (chl, &rsp, username, password);
			outstr = g_base64_encode((void *)&rsp, SmbLength(&rsp));
			printf("KK %s\n", outstr);
			fflush(stdout);
			g_free(outstr);
		} else {
			printf("Unknown request\n");
			exit(1);
		}
	}

}
