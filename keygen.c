/**
 * keygen
 *  Generates a random key of specified length using A-Z charset.
 *  Output is written to stdout with a trailing newline.
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {    
    if(argc < 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        exit(1);
    }

    srand(time(NULL));

    int keyLength = atoi(argv[1]);
    char *key = malloc((keyLength + 1) * sizeof(char));
    if(key == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for(int i = 0; i < keyLength; i++) {
        char c = charset[rand() % 26];
        key[i] = c;
    }
    key[keyLength] = '\n';
    
    fwrite(key, sizeof(char), keyLength + 1, stdout);
    
    free(key);
    return 0;
}