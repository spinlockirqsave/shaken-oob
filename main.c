#include <stdio.h>
#include <wiringPi.h>
#include <stir_shaken.h>


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
    char *s = NULL;
	stir_shaken_passport_t passport = { 0 };
    stir_shaken_passport_params_t params = { .x5u = "shaken.signalwire.com/oob/sp.pem", .attest = "A", .desttn_key = "tn", .desttn_val = "01256 533 573", .iat = time(NULL), .origtn_key = "tn", .origtn_val = "Oob Shaken", .origid = "TBD", .ppt_ignore = 1};

	
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_init(&ss, &passport, &params, sp.keys.priv_raw, sp.keys.priv_raw_len)) {
		goto fail;
	}

	s = stir_shaken_passport_dump_str(&passport, 1);

	printf("PASSporT is:\n%s\n", s);
	stir_shaken_free_jwt_str(s); s = NULL;

    // Encode using default key
	if (STIR_SHAKEN_STATUS_OK != stir_shaken_passport_sign(&ss, &passport, sp.keys.priv_raw, sp.keys.priv_raw_len, &s))
	{
		goto fail;
	}

	printf("Encoded PASSporT is:\n%s\n", s);
	stir_shaken_free_jwt_str(s); s = NULL;
	

fail:
	PRINT_SHAKEN_ERROR_IF_SET
	exit(EXIT_FAILURE);
}

int main(void)
{
	// Switch: Physical pin 31, BCM GPIO6, and WiringPi pin 22.
	const int pin = 22;

	init_shaken();

	wiringPiSetup();
	pinMode(pin, INPUT);
	pullUpDnControl(pin, PUD_DOWN);

	while (1) {
		if (digitalRead(pin) == LOW) {

			fprintf(stderr, "Pin is LOW\n");

			do_shaken();
			printf("Caller authenticated.\n");

		} else {
			fprintf(stderr, "Pin is HIGH\n");
		}
		delay(500);
	}

	return 0;
}
