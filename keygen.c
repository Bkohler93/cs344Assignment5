/*
* This program generates a key consisting of characters A-Z + space char. The number of 
* characters in the key is determined by a command line argument. output is a character array with 
* the random key generated with a newline character appended to the end of the array.
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


//this function generates a random key with chars A-Z and space chars.
//stores key on heap, returns the key as a C-style string
char *generate_key(int num_chars);

int main(int argc, char *argv[]) {

	//use random seed for rand() function
	srand(time(NULL)); 

	//int to hold number of characters to generate
	int num_chars; 

	//error check to be sure two (executable + number of chars to generate) CLA's are entered by the user
	if (argc != 2){
		fprintf(stderr, "USAGE: enter the numnber of characters you wish to generate a key for\n");
		exit(0);
	}

	//store the number the user entered as an integer into num_chars, add one for last newline char
	num_chars = atoi(argv[1]) + 1;

	//generate random key
	char *key = generate_key(num_chars);

	//write key to stdout
	write(1, key, num_chars);

	//free memory taken up by key
	free(key);

	return 0;
}

char* generate_key(int num_chars) {

	char rand_char; //single random character generated
	int rand_int; //random integer generated from rand()
	char* rand_key; //store random key generated below

	//allocate memory for key
	rand_key = malloc(num_chars); 	

	//generate random key
	for (int i = 0; i < num_chars; ++i) {

		//add 65 to a random number 0-27 in order to get to start of alphabet ('A') in ASCII code 
		rand_int = (rand() % 27) + 65; 

		//convert random int to char, if random int is one after ASCII for 'Z' set to space char
		rand_char = (rand_int == 91) ?
			' ' : rand_int;

		//set current index of random key string to randomly generated character
		rand_key[i] = rand_char;
	}

	rand_key[num_chars - 1] = '\n';

	return rand_key;
}