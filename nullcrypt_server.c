/**
 * nullcrypt_server
 *  Listens for connections from nullcrypt_client on the specified port. Forks a
 *  child process per connection to verify identity, receive text and key,
 *  perform Vigenère encryption or decryption, and return the result to the client.
 */

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void error(const char *msg);
void setupAddressStruct(struct sockaddr_in *address, int portNumber);
int sendAll(int socket, char *buffer, int bufferLen);
int recvAll(int socket, char *buffer, int bufferLen);
char *encrypt(char* text, char* key);
char *decrypt(char* text, char* key);

int main(int argc, char *argv[]){
    // check usage & argc
    if(argc < 2) {
        fprintf(stderr, "Usage: %s port\n", argv[0]);
        exit(1);
    }

    int connectionSocket;
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo = sizeof(clientAddress);

    // Create the socket that will listen for connections 
    int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if(listenSocket < 0) {
        error("ERROR opening socket");
    }

    // Setup port reuse
    int optVal = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(int));

    // Set up the address struct of the server socket
    setupAddressStruct(&serverAddress, atoi(argv[1]));

    // Associate the socket to the port
    if(bind(listenSocket,
            (struct sockaddr *)&serverAddress,
            sizeof(serverAddress)) < 0) {
        error("ERROR on binding");
    }

    // Start listening for connections. Allow up to 5 connections to queue up
    listen(listenSocket, 5);

    // Accept a connection. The server will block until a client connects
    while(1){
        // Reap zombies
        waitpid(-1, NULL, WNOHANG);

        // Accept the connection request which creates a connection socket
        connectionSocket = accept(listenSocket,
                                (struct sockaddr *)&clientAddress,
                                &sizeOfClientInfo);
        if(connectionSocket < 0){
            error("ERROR on accept");
        }

        // FORK
        pid_t childPid = fork();
        if(childPid == -1){
            error("ERROR on fork");
        } else if(childPid == 0) {
            // Child does not need listenSocket
            close(listenSocket);

            // Allocate and receive client identity
            char identity[17];
            memset(identity, '\0', sizeof(identity));
            recvAll(connectionSocket, identity, 16);

            // Handshake handler
            if(strcmp(identity, "nullcrypt_client") != 0) {
                sendAll(connectionSocket, "no", 2);
                close(connectionSocket);
                exit(1);
            } 
            sendAll(connectionSocket, "ok", 2);

            // Receive encrypt/decrypt option
            char mode;
            recv(connectionSocket, &mode, 1, 0);
            
            // Receive text length from client
            int textLen;
            if(recvAll(connectionSocket, (char *)&textLen, sizeof(int)) == -1) {
                fprintf(stderr, "Error: failed to receive text length from client\n");
                exit(1);
            };

            // Receive text from client
            char* text = malloc((textLen + 1) * sizeof(char));
            memset(text, '\0', textLen + 1);
            if(recvAll(connectionSocket, text, textLen) == -1) {
                fprintf(stderr, "Error: failed to receive text from client\n");
                exit(1);
            }

            // Receive key length from client
            int keyLen;
            if(recvAll(connectionSocket, (char *)&keyLen, sizeof(int)) == -1) {
                fprintf(stderr, "Error: failed to receive key length from client\n");
                exit(1);
            };

            // Receive key from client
            char* key = malloc((keyLen + 1) * sizeof(char));
            memset(key, '\0', keyLen + 1);
            if(recvAll(connectionSocket, key, keyLen) == -1) {
                fprintf(stderr, "Error: failed to receive key from client\n");
                exit(1);
            }

            if(mode == 'e'){
                // Encrypt and send encrypted text back to client
                char* encText = encrypt(text, key);
                if(sendAll(connectionSocket, encText, textLen) == -1) {
                    fprintf(stderr, "Error: failed to send encrypted text to client\n");
                    exit(1);
                }
                free(encText);
            } else {
                // Decrypt and send decrypted text back to client
                char* decText = decrypt(text, key);
                if(sendAll(connectionSocket, decText, textLen) == -1) {
                    fprintf(stderr, "Error: failed to send decrypted text to client\n");
                    exit(1);
                }
                free(decText);
            }
            
            // Free memory, close socket, and exit child
            free(text);
            free(key);
            close(connectionSocket);
            exit(0);
        } else {
            // Parent no longer needs connection socket after forking
            close(connectionSocket);
        }
    }
    // Close the listenSocket
    close(listenSocket);
    return 0;
}

/* Error Function used for reporting issues */
void error(const char *msg) {
    perror(msg);
    exit(1);
}

// Setup the address struct for the server socket
void setupAddressStruct(struct sockaddr_in *address, int portNumber) {
    
    // Clear out the address struct
    memset((char*) address, '\0', sizeof(*address));

    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number
    address->sin_port = htons(portNumber);
    // Allow a client at any address to connect to this server
    address->sin_addr.s_addr = INADDR_ANY;
}

/**
 * sendAll
 *  Repeatedly send buffer until all bytes have been sent. TCP guarantees order, so we can
 *  use total as an offset of buffer to pickup where we left off. If send returns an error, 
 *  we return -1 to the caller.
 */
int sendAll(int socket, char *buffer, int bufferLen) {
    int total = 0;                  // bytes sent
    int bytesLeft = bufferLen;      // how many left to send
    int n = 0;

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

/**
 * recvAll
 *  Loops recv until we've verified that all bytes have been received.
 *  TCP guarantees order, so we can use total as an offset on buffer to 
 *  write from what was lost.
 */
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

    // return -1 on failure, 0 on success
    return n == -1 ? -1 : 0;
}

/**
 * encrypt
 *  Calculates index values for text and key [0, 25] using Vigenère cipher.
 *  Key repeats via modulo indexing. textVal + keyVal mod 26 produces ciphertext.
 */
char *encrypt(char *text, char *key) {
    int bufferLength = strlen(text);
    int keyLen = strlen(key);
    char *buffer = malloc((bufferLength + 1) * sizeof(char));
    memset(buffer, '\0', bufferLength + 1);

    for(int i = 0; i < bufferLength; i++) {
        int textVal = text[i] - 'A';
        int keyVal = key[i % keyLen] - 'A';
        int encVal = (textVal + keyVal) % 26;
        buffer[i] = 'A' + encVal;
    }

    return buffer;
}

/**
 * decrypt
 *  Reverses Vigenère encryption. keyVal is subtracted from textVal with +26
 *  before modulo to prevent negative values.
 */
char *decrypt(char *text, char *key) {
    int bufferLength = strlen(text);
    int keyLen = strlen(key);
    char *buffer = malloc((bufferLength + 1) * sizeof(char));
    memset(buffer, '\0', bufferLength + 1);

    for(int i = 0; i < bufferLength; i++) {
        int textVal =  text[i] - 'A';
        int keyVal = key[i % keyLen] - 'A';
        int decVal = (textVal - keyVal + 26) % 26;
        buffer[i] = 'A' + decVal;
    }

    return buffer;
}