/**
 * nullcrypt_client
 *  Connects to nullcrypt_server on the specified port. Sends mode flag (-e/-d),
 *  text and key for Vigenère encryption or decryption, and writes result to stdout.
 */

#include <netdb.h>    // gethostbyname()
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>   // send(), recv()
#include <unistd.h>

void error(const char *msg);
char *openFile(char *filename);
void setupAddressStruct(struct sockaddr_in *address, int portNumber, char *hostName);
void validateInput(char *text);
int sendAll(int socket, char *buffer, int bufferLen);
int recvAll(int socket, char *buffer, int bufferLen);

int main(int argc, char *argv[]) {
    // Check usage & arguments
    if ( argc < 5) {
        fprintf(stderr, "USAGE: %s -e/-d textfile keyfile port\n", argv[0]);
        exit(0);
    }

    int socketFD;
    struct sockaddr_in serverAddress;

    char *text = openFile(argv[2]);
    char *key = openFile(argv[3]);
    char *identity = "nullcrypt_client";

    validateInput(text, key);

    // Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) {
        error("CLIENT: ERROR opening socket\n");
    }

    // Setup the server address struct
    setupAddressStruct(&serverAddress, atoi(argv[4]), "localhost");

    // Connect to server, exit code 2 on failure
    if(connect(socketFD,
        (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
        fprintf(stderr, "Error: could not contact enc_server on port %s\n", argv[4]);
        exit(2);
    }

    // Send identity handshake
    sendAll(socketFD, identity, strlen(identity));

    // Wait for server confirmation
    char confirm[3];
    memset(confirm, '\0', sizeof(confirm));
    recvAll(socketFD, confirm, 2);
    if(strcmp(confirm, "ok") != 0) {
        fprintf(stderr, "Error: could not contact nullcrypt_server on port %s\n", argv[4]);
        exit(2);
    }

    char mode = (strcmp(argv[1], "-e") == 0) ? 'e' : 'd';
    if(send(socketFD, &mode, 1, 0) == -1){
        fprintf(stderr, "Error: failed to send mode to server\n");
        exit(1);
    }

    // Send text buffer to server
    int textLen = strlen(text);
    if(send(socketFD, &textLen, sizeof(int), 0) == -1) {
        fprintf(stderr, "Error: failed to send text length to server\n");
        exit(1);
    }
    if(sendAll(socketFD, text, strlen(text)) == - 1){
        fprintf(stderr, "Error: failed to send text to server\n");
        exit(1);
    }

    // Send key buffer to server
    int keyLen = strlen(key);
        if(send(socketFD, &keyLen, sizeof(int), 0) == -1) {
        fprintf(stderr, "Error: failed to send key length to server\n");
        exit(1);
    }
    if(sendAll(socketFD, key, strlen(key)) == - 1){
        fprintf(stderr, "Error: failed to send key to server\n");
        exit(1);
    }

    // Clear out text buffer again for reuse
    memset(text, '\0', textLen + 1);
    if(recvAll(socketFD, text, textLen) == -1) {
        fprintf(stderr, "Error: failed to receive encrypted text from server\n");
        exit(1);
    }

    printf("%s\n", text);

    // Close the socket and free heap
    close(socketFD);
    free(text);
    free(key);
    return 0;
}

// Error function used for reporting issues
void error(const char *msg) {
    perror(msg);
    exit(0);
}

// Setup the address struct
void setupAddressStruct(struct sockaddr_in *address,
    int portNumber,
    char *hostName){
    // Clear out the address struct
    memset((char*) address, '\0', sizeof(*address));

    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number
    address->sin_port = htons(portNumber);

    // Get the DNS entry for the host name
    struct hostent* hostInfo = gethostbyname(hostName);
    if(hostInfo == NULL) {
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(0);
    }

    // Copy the first IP address from the DNS entry to sin_addr.s_addr  
    memcpy((char*) &address->sin_addr.s_addr,
        hostInfo->h_addr_list[0],
        hostInfo->h_length);
}

char *openFile(char *filename) {
    FILE *textFile = fopen(filename, "r");
    if(textFile == NULL) {
        fprintf(stderr, "Error opening file %s\n", filename);
        exit(1);
    }

    // get file length
    fseek(textFile, 0, SEEK_END);
    long fileLength = ftell(textFile);
    rewind(textFile);

    // malloc buffer, adding a byte incase '\n' is missing for when strcspn adds '\0'
    char *text = malloc((fileLength + 1) * sizeof(char));
    if(text == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    memset(text, '\0', fileLength + 1);

    fread(text, sizeof(char), fileLength, textFile);
    fclose(textFile);

    if(text[fileLength -1 ] == '\n')
        text[fileLength - 1] = '\0';

    return text;
}

void validateInput(char *text) {
    for(char *c = text; *c != '\0'; c++) {
        if((*c < 'A' || *c > 'Z')) {
            fprintf(stderr, "Error: input contains bad characters\n");
            exit(1);
        }
    }
}

int sendAll(int socket, char *buffer, int bufferLen) {
    int total = 0;                // bytes sent
    int bytesLeft = bufferLen;    // how many left to send
    int n = 0;

    /**
     * Repeatedly send buffer until all bytes have been sent. TCP guarantees order, so we can
     * use total as an offset of buffer to pickup where we left off. If send returns an error, 
     * we return -1 to the caller.
     */
    while(total < bufferLen) {
        n = send(socket, buffer + total, bytesLeft, 0);
        if(n == -1)
            break;
        total += n;
        bytesLeft -= n;
    }

    // return -1 on failure, 0 on success
    return n == -1 ? -1 : 0;
}

int recvAll(int socket, char *buffer, int bufferLen) {
    int total = 0;
    int bytesLeft = bufferLen;
    int n = 0;

    while(total < bufferLen) {
        n = recv(socket, buffer + total, bytesLeft, 0);
        // Handles edge case of server connection closed n == 0, prevents inf loop.
        if(n == -1 || n == 0)
            break;
        total += n;
        bytesLeft -= n;
    }

    return n == -1 ? -1 : 0;
}