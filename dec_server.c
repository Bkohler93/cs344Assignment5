#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "const.h"

//create mutex and condition vars
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t threadFree = PTHREAD_COND_INITIALIZER;
pthread_cond_t clientAvail = PTHREAD_COND_INITIALIZER;

//shared resources. Store the socket connection currently being assigned to a thread. Store number of threads occupied
int newSocket = -3; //no newsocket yet, set to negative number
int numThreadsBusy = 0; //no threads are busy yet


// Error function used for reporting issues
void error(const char *msg) {
  perror(msg);
  exit(1);
} 

//check if data was sucessfully received from client
void checkNumRead(int numRead) {
  if (numRead < 0) {
    error("SERVER: Cannot read from socket");
  }
}

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, 
                        int portNumber){
 
  // Clear out the address struct
  memset((char*) address, '\0', sizeof(*address)); 

  // The address should be network capable
  address->sin_family = AF_INET;
  // Store the port number
  address->sin_port = htons(portNumber);
  // Allow a client at any address to connect to this server
  address->sin_addr.s_addr = INADDR_ANY;
}

/*
* this function checks to be sure the client attempting to connect is the encryption client
* Server receives a single character from the client, and if this character is not an 'e' then
* the server will send back an 'r' standing for rejected. If this character is an 'e' then
* the server sends back an 'a' meaning accepted.
*/
int clientCheck(int connectionSocket, struct sockaddr_in *clientAddress) {
  char rec;
  int numRes = recv(connectionSocket, &rec, sizeof(rec), 0);

  if (rec != 'd') {
    send(connectionSocket, "r", 1, 0);
    fprintf(stderr, "SERVER: Rejected client\n");
    close(connectionSocket);

    //go back to start of while loop to accept new client
    return 0;

  } else {
    send(connectionSocket, "a", 1, 0);
    return 1;
  }

}

/*
* This function receives chunks of 1000 characters from the client and stores each chunk in
* a 2d buffer. 
*/
int fillTextChunks(char ***textChunks, int connectionSocket) {

  //receive number of chunks to be received from client
  int numChunks; 
  int numRead;
  numRead = recv(connectionSocket, &numChunks, sizeof(numChunks), 0);

  //error check recv()
  checkNumRead(numRead);

  //fill number of chunks to textChunks array
  *textChunks = malloc(sizeof(char *) * numChunks);
  memset(*textChunks, '\0', numChunks);

  //temporary buffer to store incoming text chunks
  char buffer[READ_BUFF];
  memset(buffer, '\0', READ_BUFF);

  // receive until '@@' is found in the current line
  int i = 0;
  while (1) {
    
    numRead = recv(connectionSocket, buffer, READ_BUFF, 0);

    checkNumRead(numRead);

    //fill into textChunks array
    (*textChunks)[i] = malloc(READ_BUFF);
    memset((*textChunks)[i], '\0', READ_BUFF);
    strcpy((*textChunks)[i], buffer);

    //find null terminating characters
    if (strstr((*textChunks)[i], "@@")) break;

    ++i;
  }

  return numChunks;
}

char decryptChar(char cypher, char key) {

  if (cypher == 32) cypher = 91; //set any space characters to the character after 'Z'
  if (key == 32) key = 91;

  //get difference between cipher and key
  int diff = (cypher - 65) - (key - 65);
  int r; //remainder

  //perform neg mod pos if diff is neg
  if (diff < 0) {
    for (int i = -1; i >= diff; i++) {
      r = diff - 27*i;

      if (r > 0) break;
    }
  } else {
    r = diff % 27;
  }

  char c = r + 65;

  if (c == 91) c = 32; //if c is the "27th" of the alphabet set it to space char

  return c;
}

/*
* this function iterates through each chunk and each character in each chunk, encrypting each character.
* This alters the plainTextChunks array into an encrypted array.
*/
void decryptText(char ***cypherTextChunks, char ***keyTextChunks) {


  int i = 0;

  //loop will run until terminating sequence has been found
  while (1) {

    int chunkLen = strlen((*cypherTextChunks)[i]);
    int stop = 0;

    for (int j = 0; j < chunkLen; j++) {

      if ((*cypherTextChunks)[i][j] == '@') {
        stop = 1;
        break;
      }

      (*cypherTextChunks)[i][j] = decryptChar((*cypherTextChunks)[i][j], (*keyTextChunks)[i][j]);
    }
    ++i;
    if (stop) break;
  }
}

/*
* Sends the encrypted text chunks back to the client (designated by connectionSocket). 
*/
void sendDecryptedText(char ***textChunks, int connectionSocket) {

  int i = 0;
  int numSent;

  while(1) {
    numSent = send(connectionSocket, (*textChunks)[i], READ_BUFF, 0);

    if (numSent < 0) {
      error("CLIENT: ERROR writing to socket");
    }

    if (strstr((*textChunks)[i], "@@")) break;
    ++i;
  }
}

void *run_thread(void *args) {
  int connectionSocket;
  int numPlainChunks;
  int numKeyChunks;
  char **plainTextChunks;
  char **keyTextChunks;

  while(1) {
    //attempt to lock m
    pthread_mutex_lock(&m);

    //wait until newSocket is a valid socket/signal that client is connected
    while (newSocket < 0) {
      pthread_cond_wait(&clientAvail, &m);
    }

    connectionSocket = newSocket; //store new client socket locally
    newSocket = -2; //change global client socket to invalid value
    ++numThreadsBusy; //thread is now busy
    pthread_mutex_unlock(&m);

    //receive plain text and key text from client
    numPlainChunks = fillTextChunks(&plainTextChunks, connectionSocket);

    numKeyChunks = fillTextChunks(&keyTextChunks, connectionSocket);

    //encrypt text
    decryptText(&plainTextChunks, &keyTextChunks);
    //send encrypted text back (stored in plainTextChunks)
    sendDecryptedText(&plainTextChunks, connectionSocket);
    //free memory from textChunks
    for (int i = 0; i < numPlainChunks; i++) {
      free(plainTextChunks[i]);
    }
    free(plainTextChunks);
    for (int i = 0; i < numKeyChunks; i++) {
      free(keyTextChunks[i]);
    }
    free(keyTextChunks);

    close(connectionSocket);

    //this thread is no longer busy
    pthread_mutex_lock(&m);
      --numThreadsBusy;
      pthread_cond_signal(&threadFree); //signal to main that thread is now free
    pthread_mutex_unlock(&m);
  }
}


int main(int argc, char *argv[]){
  int socketConnect, charsRead;

  struct sockaddr_in serverAddress, clientAddress;
  socklen_t sizeOfClientInfo = sizeof(clientAddress);

  // Check usage & args
  if (argc < 2) { 
    fprintf(stderr,"USAGE: %s port\n", argv[0]); 
    exit(1);
  } 

  // Create the socket that will listen for connections
  int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (listenSocket < 0) {
    error("ERROR opening socket");
  }
  // Set up the address struct for the server socket
  setupAddressStruct(&serverAddress, atoi(argv[1]));

  // Associate the socket to the port
  if (bind(listenSocket, 
          (struct sockaddr *)&serverAddress, 
          sizeof(serverAddress)) < 0){
    error("ERROR on binding");
  }

  //create 5 threads to be used
  pthread_t t1, t2, t3, t4, t5;
  pthread_create(&t1, NULL, run_thread, NULL);
  pthread_create(&t2, NULL, run_thread, NULL);
  pthread_create(&t3, NULL, run_thread, NULL);
  pthread_create(&t4, NULL, run_thread, NULL);
  pthread_create(&t5, NULL, run_thread, NULL);


  // Start listening for connetions. Allow up to 20 connections to queue up
  listen(listenSocket, 20); 

  // Accept a connection, blocking if one is not available until one connects
  while(1){

    //lock mutex then sleep until a thread is free
    pthread_mutex_lock(&m);
    while (numThreadsBusy == 5) {
      pthread_cond_wait(&threadFree, &m);
    }
    pthread_mutex_unlock(&m);

    // Accept the connection request which creates a connection socket
    socketConnect = accept(listenSocket, 
                (struct sockaddr *)&clientAddress, 
                &sizeOfClientInfo); 
    if (socketConnect < 0){
      error("ERROR on accept");
    }
    //receive client message, check to be sure it is encryption client
    if (!clientCheck(socketConnect, &clientAddress)) {
      continue;
    } 

    //
    pthread_mutex_lock(&m);

    //set newSocket to socketConnect from new client
    newSocket = socketConnect;

    pthread_cond_signal(&clientAvail);
    pthread_mutex_unlock(&m);
  }
    close(listenSocket);
    return 0; 
}
