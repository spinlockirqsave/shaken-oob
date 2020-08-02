#include <stdio.h>
#include <wiringPi.h>

int main(void)
{
	// Switch: Physical pin 31, BCM GPIO6, and WiringPi pin 22.
	const int pin = 22;

	wiringPiSetup();

	pinMode(pin, INPUT);
	pullUpDnControl(pin, PUD_DOWN);

	while (1) {
		if (digitalRead(pin) == LOW) {
			fprintf(stderr, "Pin is LOW\n");
		} else {
			fprintf(stderr, "Pin is HIGH\n");
		}
		delay(500);
	}

	return 0;
}
