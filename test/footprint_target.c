/*
 * A process with a footprint the test controls.
 *
 * Compiled per test run rather than shipped: the watchdog matches its target by
 * resolved executable path, so the target needs a path unique to the test. A
 * copy of a system binary cannot serve - macOS SIGKILLs a copied platform
 * binary (verified: signature validation refuses it) - and a script cannot
 * either, since proc_pidpath reports the interpreter, not the script.
 *
 * Usage: footprint-target <mib> <seconds>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    long mib = (argc > 1) ? atol(argv[1]) : 0;
    long seconds = (argc > 2) ? atol(argv[2]) : 60;

    if (mib > 0) {
        size_t bytes = (size_t)mib * 1024 * 1024;
        char *block = malloc(bytes);
        if (block == NULL) {
            fprintf(stderr, "allocation of %ld MiB failed\n", mib);
            return 1;
        }
        /* Dirty every page: an untouched allocation is address space, not
         * footprint, so a test that only malloc'd would measure nothing. */
        memset(block, 1, bytes);
    }

    /* The harness waits for this before measuring, so the allocation above is
     * guaranteed to be in the ledger by the time a sample is taken. */
    fprintf(stderr, "ready\n");
    fflush(stderr);

    sleep((unsigned int)seconds);
    return 0;
}
