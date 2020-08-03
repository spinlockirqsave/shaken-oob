#include <stdio.h>
#include <wiringPi.h>
#include <stir_shaken.h>

#include <stdio.h>
#include <errno.h>
#include	<stdarg.h>		/* ANSI C header file */
#include	<syslog.h>		/* for syslog() */
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>

#include <sys/resource.h>

#define SPOOFED_CALL_DEMO 0


stir_shaken_context_t ss = { 0 };
const char *error_description = NULL;
stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;

stir_shaken_sp_t sp = { 0 };

#define PRINT_SHAKEN_ERROR_IF_SET \
    if (stir_shaken_is_error_set(&ss)) { \
		error_description = stir_shaken_get_error(&ss, &error_code); \
		printf("Error description is: %s\n", error_description); \
		printf("Error code is: %d\n", error_code); \
	}

int tcp_send(char *data, int datalen);

static void init_shaken(void)
{
	printf("Loading keys...\n");
	sp.keys.priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(&ss, &sp.keys.private_key, NULL, "priv.pem", NULL, sp.keys.priv_raw, &sp.keys.priv_raw_len)) {
		goto fail;
	}

	return;

fail:
	PRINT_SHAKEN_ERROR_IF_SET
	exit(EXIT_FAILURE);
}

static void do_shaken(void)
{
    char *s = NULL, *passport_encoded = NULL;
	int n = 0;
	stir_shaken_passport_t passport = { 0 };
    stir_shaken_passport_params_t params = { .x5u = "shaken.signalwire.com/oob/sp.pem", .attest = "A", .desttn_key = "tn", .desttn_val = "01256 533 573", .iat = time(NULL), .origtn_key = "tn", .origtn_val = "Oob Shaken", .origid = "TBD", .ppt_ignore = 1};

#if SPOOFED_CALL_DEMO
	char origchsum[STIR_SHAKEN_BUFLEN] = { 0 };
	char spoofed_passport[STIR_SHAKEN_BUFLEN] = { 0 };
	char *p = NULL;
#endif

	
	printf("PASSporT init...\n");
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_init(&ss, &passport, &params, sp.keys.priv_raw, sp.keys.priv_raw_len)) {
		printf("PASSporT init failed...\n");
		goto fail;
	}

	printf("PASSporT dump...\n");
	s = stir_shaken_passport_dump_str(&passport, 1);

	printf("PASSporT is:\n%s\n", s);
	stir_shaken_free_jwt_str(s); s = NULL;

    // Encode using default key
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_sign(&ss, &passport, sp.keys.priv_raw, sp.keys.priv_raw_len, &passport_encoded))
	{
		goto fail;
	}

	printf("Encoded PASSporT is:\n%s\n\n", passport_encoded);

#if SPOOFED_CALL_DEMO

	p = strchr(passport_encoded, '.');
	p = strchr(p + 1, '.');
	p++;
	strcpy(origchsum, p);
	printf("Original checksum is: %s\n", origchsum);
	stir_shaken_free_jwt_str(passport_encoded);
	passport_encoded = NULL;


	printf("\n+++ SPOOFING CallerID!\n\n");
	if (jwt_del_grants(passport.jwt, "orig") != 0) {
		printf("Oops. SPOOFING failed to remove 'orig' grant\n");
		goto fail;
	}
	if (jwt_add_grant(passport.jwt, "orig", "{\"tn\":\"Eric Clapton\"}") != 0) {
		printf("Oops. SPOOFING failed to add fake 'orig' grant\n");
		goto fail;
	}
	s = stir_shaken_passport_dump_str(&passport, 1);
	printf("SPOOFED PASSporT is:\n%s\n", s);
	jwt_free_str(s); s = NULL;

	s = jwt_encode_str(passport.jwt);
	printf("SPOOFED PASSporT properly encoeded is:\n%s\n", s);

	printf("\nNow making result PASSporT by joining SPOOFED headers and grants (encoded) with previous (original) checksum...\n");
	strcpy(spoofed_passport, s);
	p = strchr(spoofed_passport, '.');
	p = strchr(p + 1, '.');
	p++;
	strcpy(p, origchsum);
	p = NULL;

	printf("\nSPOOFED PASSporT badly encoeded (result) is:\n%s\n\n", spoofed_passport);

	passport_encoded = &spoofed_passport[0];
	s = NULL;
#endif

	if ((n = tcp_send(passport_encoded, strlen(passport_encoded))) <= 0) {
		printf("Failed to send PASSporT\n");
		goto fail;
	}

	printf("PASSporT sent (%d bytes)...\n", n);

#if SPOOFED_CALL_DEMO
#else
	stir_shaken_free_jwt_str(passport_encoded);
#endif
	//stir_shaken_destroy_http_request(&http_req);
	return;
	

fail:
	PRINT_SHAKEN_ERROR_IF_SET
	exit(EXIT_FAILURE);
}
	
int		sockfd;
struct sockaddr_in	servaddr;
#define SERV_PORT 9877
//#define SERVER_ADDRESS "shaken.signalwire.com"
#define SERVER_ADDRESS "3.8.193.142"

int tcp_init(void)
{

	printf("TCP: creating socket...\n");
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("TCP: Cannot connect init socket\n");
		return -1;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons( SERV_PORT);

	printf("TCP: inet_pton......\n");
	if (inet_pton(AF_INET, SERVER_ADDRESS, &servaddr.sin_addr) <= 0) {
		printf("TCP: Cannot assign server address for the socket\n");
		return -1;
	}

	printf("TCP: connecting socket...\n");
	if(connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
		printf("TCP: Cannot connect to server\n");
		return -1;
	}
	return 0;
}

int tcp_send(char *data, int datalen)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = ( const char*) data;
	nleft = datalen;
	while (nleft > 0) {
		if ( (nwritten = write(sockfd, ptr, nleft)) <= 0) {
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return datalen;
}

int main(void)
{
	// Switch: Physical pin 31, BCM GPIO6, and WiringPi pin GPIO22.
	const int pin = 22;


	printf("Starting TCP...\n");
	if (tcp_init() < 0) {
		printf("Cannot init TCP\n");
		exit(EXIT_FAILURE);
	}

	printf("Starting Shaken...\n");
	init_shaken();
			do_shaken();

	printf("Configuring Pi GPIO...\n");
	wiringPiSetup();
	pinMode(pin, INPUT);
	pullUpDnControl(pin, PUD_DOWN);


	printf("\nReady...\n\n");
	while (1) {
		if (digitalRead(pin) == LOW) {

			fprintf(stderr, "\n\nAuthenticating outgoing call...\n\n");

			do_shaken();
			printf("\n\nCaller authenticated.\n\n");
			return 0;

		} else {
			fprintf(stderr, "Waiting for the call...\n");
		}
		delay(500);
	}

	return 0;
}
