#include <stdio.h>
#include <wiringPi.h>

int main(void)
{
	// Switch: Physical pin 31, BCM GPIO6, and WiringPi pin 22.
	const int button = 22;

	wiringPiSetup();

	pinMode(button, INPUT);

	while (1) {
		if (digitalRead(button) == LOW) {
			fprintf(stderr, "Switch is pressed\n");
		} else {
			fprintf(stderr, "Switch is released\n");
		}
		delay(500);
	}

	return 0;
}