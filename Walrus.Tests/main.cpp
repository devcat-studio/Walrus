#include <stdio.h>
#include <walrus.h>

extern "C" int walrus_run_tests(void);

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	if (walrus_run_tests()) {
		fprintf(stderr, "done.\n");
		return 0;
	} else {
		fprintf(stderr, "tests disabled.\n");
		return 1;
	}
}
