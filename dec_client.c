#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()
#include <errno.h>
#include "const.h"


// Error function used for reporting issues
void error(const char *msg) { 
  perror(msg); 
  exit(0); 
} 

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, 
                        int portNumber, 
                        char* hostname){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;
  // Store the port number
  address->sin_port = htons(portNumber);

  // Get the DNS entry for this host name
  struct hostent* hostInfo = gethostbyname(hostname); 
  if (hostInfo == NULL) { 
    fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
    exit(0); 
  }
  // Copy the first IP address from the DNS entry to sin_addr.s_addr
  memcpy((char*) &address->sin_addr.s_addr, 
        hostInfo->h_addr_list[0],
        hostInfo->h_length);
}

void initialMessage(int socketFD, char* port) {

  //send client-message to server
  char res;
  int numSend = send(socketFD, "d", 1, 0); 

  //ensure message was sent
  if (numSend < 0) {
    fprintf(stderr, "CLIENT: Unable to submit client-type message to host.\n");
  }

  int numRec = recv(socketFD, &res, sizeof(res), 0);

  //ensure message was sent
  if (numRec < 0) {
    fprintf(stderr, "CLIENT: Unable to receieve host response from client-type message\n");
    exit(0);
  }

  //reject response receieved from server
  //exit program with error
  if (res == 'r') {
    char err[100];
    snprintf(err, 100, "CLIENT: Port %s only accepts connections from encryption client", port);
    errno = 111;
    perror(err);
    exit(2);
  } 
}

/*
* This function takes in a 2d buffer to allow storage of ~100,000 (100 * 1002) characters from an input file. 
* It reads in chunks of 1000 bytes, storing characters into the buffer until no bytes can be read from the file. The total number of characters stored as well as the number of chunks read is then returned.
*/
int* fillTextChunks(char textChunks[NUM_CHUNKS][READ_BUFF], char* fileName) {

  int fileLen = 0;

  //set memory to null characters
  for (int i = 0; i < NUM_CHUNKS; i++) {
    memset(textChunks[i], '\0', READ_BUFF);
  }
  // open file in read-only mode 
  FILE* filePtr = fopen(fileName, "r");

  if (!filePtr) {
    char err[50];
    snprintf(err, 50, "Error opening file '%s'", fileName);
    error(err);
  }

  /*
  * store chunks of text into plaintext buffers until fgets() returns a null ptr, EOF reached. Stores in chunks of 1000 bytes (READ_BUFF - 2), each chunk gets stored into an index of textChunks[].
  */
  int line = 0;
  char *p;
  while (fgets(textChunks[line], READ_BUFF - 2, filePtr)) {

    int lineLen = strlen(textChunks[line]);


    //remove newline char if a short chunk (end of plaintext) is received (last two characters reserved for terminating sequence)
    if (p = strstr(textChunks[line], "\n")) {
      *p = '\0';
      --lineLen;
    }

    //check for invalid characters
    for (int j = 0; j < lineLen; j++) {
      char c = textChunks[line][j];
      if (c != 32 && (c < 65 || c > 90)) {
        fprintf(stderr,"CLIENT: Invalid characters found in '%s'\n", fileName);
        exit(0);
      }
    }

    //calculate length before adding null terminating sequence then add null terminating sequence.
    fileLen += lineLen;

    ++line;
  }
  //add null terminating string to last chunk of text
  strcat(textChunks[line - 1], "@@");
  fclose(filePtr);

  //store total number of characters and number of lines/chunks read
  //number of lines/chunks will be 1 less than currently stored
  // due to current value used to break out of while loop above
  static int fileNums[2];
  fileNums[0] = fileLen;
  fileNums[1] = line;
  return fileNums;
}

void sendText(char textChunks[NUM_CHUNKS][READ_BUFF], int socketFD, int numChunks) {

  int i = 0;
  int numSent;

  //send number of chunks
  numSent = send(socketFD, &numChunks, sizeof(numChunks), 0);

  if (numSent < 0) error("CLIENT: error writing to socket");

  while(1) {

    numSent = send(socketFD, textChunks[i], READ_BUFF, 0);

    if (numSent < 0) {
      error("CLIENT: ERROR writing to socket");
    }

    if (strstr(textChunks[i], "@@")) break;
    ++i;
  }
}

void receiveDecryptedText(char textChunks[NUM_CHUNKS][READ_BUFF], int socketFD) {

    int i = 0;
    int numRead;
    while(1) {

      numRead = recv(socketFD, textChunks[i], READ_BUFF, 0);

      if (numRead < 0) {
        error("CLIENT: Cannot read from socket");
      } else if (numRead == 0) {
        break;
      }
      if (strstr(textChunks[i], "@@")) {
        break;
      }

      ++i;
    }
}

//send encrypted text to stdout
void returnDecryptedText(char textChunks[NUM_CHUNKS][READ_BUFF]) {

  //track which chunk is being returned
  int i = 0;

  //find null terminating "@@" 
  char *ptr;

  while (1) {

    if (ptr = strstr(textChunks[i], "@@")) {
      *ptr = '\n';
      *(++ptr) = '\0';

      printf("%s", textChunks[i]);
      break;
    }

    printf("%s", textChunks[i++]);
  }
}

int main(int argc, char *argv[]) {
  int socketFD, portNumber;
  struct sockaddr_in serverAddress;

  // Check usage & args
  if (argc < 4) { 
    fprintf(stderr,"USAGE: %s plaintext_file key_file port\n", argv[0]); 
    exit(0); 
  } 

  /* Store plain text and key text from files given in command line arguments.
  *  Text buffers support 100 transmissions of 1002 characters (extra 2 characters for terminating '@@' sequence).
  * Store number of characters/chunks from each file.
  */
  char cypherTextChunks[NUM_CHUNKS][READ_BUFF];
  int *numsCypher = fillTextChunks(cypherTextChunks, argv[1]); 
  int numCharsCypher = numsCypher[0];
  int numChunksCypher = numsCypher[1];

  char keyTextChunks[NUM_CHUNKS][READ_BUFF];
  int *numsKey = fillTextChunks(keyTextChunks, argv[2]);
  int numCharsKey = numsKey[0];
  int numChunksKey = numsKey[1];


  if (numCharsKey < numCharsCypher) {
    fprintf(stderr, "CLIENT: Keyfile %s has fewer characters than Textfile %s\n", argv[2], argv[1]);
    exit(0);
  }

  // Create a socket
  socketFD = socket(AF_INET, SOCK_STREAM, 0); 
  if (socketFD < 0){
    error("CLIENT: ERROR opening socket");
  }

   // Set up the server address struct
  setupAddressStruct(&serverAddress, atoi(argv[3]), "localhost");

  // Connect to server
  if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
    error("CLIENT: ERROR connecting");
  }

  //send client-type message to port number from command line arg (establish correct connection)
  initialMessage(socketFD, argv[3]);

  //send plain text
  sendText(cypherTextChunks, socketFD, numChunksCypher);

  //send key text
  sendText(keyTextChunks, socketFD, numChunksKey);

  //receive encrypted text, store into plainTextFile buffer
  receiveDecryptedText(cypherTextChunks, socketFD); 

  //write encrypted text to stdout
  returnDecryptedText(cypherTextChunks);


  // Close the socket
  close(socketFD); 
  return 0;
}