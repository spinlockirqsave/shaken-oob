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
	stir_shaken_passport_t passport = { 0 };
    stir_shaken_passport_params_t params = { .x5u = "shaken.signalwire.com/oob/sp.pem", .attest = "A", .desttn_key = "tn", .desttn_val = "01256 533 573", .iat = time(NULL), .origtn_key = "tn", .origtn_val = "Oob Shaken", .origid = "TBD", .ppt_ignore = 1};
	//stir_shaken_http_req_t http_req = { 0 };

	
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_init(&ss, &passport, &params, sp.keys.priv_raw, sp.keys.priv_raw_len)) {
		goto fail;
	}

	s = stir_shaken_passport_dump_str(&passport, 1);

	printf("PASSporT is:\n%s\n", s);
	stir_shaken_free_jwt_str(s); s = NULL;

    // Encode using default key
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_sign(&ss, &passport, sp.keys.priv_raw, sp.keys.priv_raw_len, &passport_encoded))
	{
		goto fail;
	}

	printf("Encoded PASSporT is:\n%s\n\n", passport_encoded);

/**	
	http_req.url = strdup("shaken.signalwire.com/oob/");
	http_req.remote_port = 80;

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_make_http_post_req(&ss, &http_req, passport_encoded, 1)) {
		goto fail;
	}

	printf("HTTP result: %ld\n", http_req.response.code);

	if (http_req.response.code != 200 && http_req.response.code != 201) {
		goto fail;
	}
**/

	if (tcp_send(passport_encoded, strlen(passport_encoded)) != 0) {
		printf("Failed to send PASSporT\n");
		goto fail;
	}

	printf("PASSporT sent...\n");

	stir_shaken_free_jwt_str(passport_encoded);
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
#define SERVER_ADDRESS "190.102.98.199"

int tcp_init(void)
{

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("TCP: Cannot connect init socket\n");
		return -1;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons( SERV_PORT);
	if (inet_pton(AF_INET, SERVER_ADDRESS, &servaddr.sin_addr) <= 0) {
		printf("TCP: Cannot assign server address for the socket\n");
		return -1;
	}

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
	return 0;
}

int main(void)
{
	// Switch: Physical pin 31, BCM GPIO6, and WiringPi pin 22.
	const int pin = 22;


	printf("Starting TCP...\n");
	if (tcp_init() < 0) {
		printf("Cannot init TCP\n");
		exit(EXIT_FAILURE);
	}

	printf("Starting Shaken...\n");
	init_shaken();

	printf("Configuring Pi GPIO...\n");
	wiringPiSetup();
	pinMode(pin, INPUT);
	pullUpDnControl(pin, PUD_DOWN);


	printf("\nReady...\n\n");
	while (1) {
		if (digitalRead(pin) == LOW) {

			fprintf(stderr, "Pin is LOW\n");

			do_shaken();
			printf("\nCaller authenticated.\n");
			return 0;

		} else {
			fprintf(stderr, "Pin is HIGH\n");
		}
		delay(500);
	}

	return 0;
}
