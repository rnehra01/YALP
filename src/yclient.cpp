#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h> 
#include <string.h>
#include <vector>
#include "globals.h"

using namespace std;

//string ROOT = "/tmp/";
void init_ydaemon();

void readFile(string file, int last = 10){
	FILE *in;
    long int pos;
    char data[100];
	int count = 0;
    in = fopen(file.c_str(), "r");
    if (in == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    fseek(in, 0, SEEK_END);
    pos = ftell(in);
    while (pos) {
        fseek(in, --pos, SEEK_SET);
        if (fgetc(in) == '\n') {
            if (count++ == last) break;
        }
    }
    
    if(count <= last ) fseek(in, 0, SEEK_SET);
    
    while (fgets(data, sizeof(data), in) != NULL) {
        fprintf(stdout, "  %s", data);
    }
    fclose(in);
}

void launch_daemon(){
	if(fork() == 0){
		init_ydaemon();
	}
}

int main(int argc, char* argv[]){

	if(argc < 2){
		printf("Usage: yapmat [args]\n");
		exit(1);
	}	
	
    int sock, len;
    struct sockaddr_in serv_addr;
    char str[100];

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(31337);
    
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0){ 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        launch_daemon();
        sleep(1);
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        	perror("connect");
        	exit(1);
        }
    }

	for(int i=1; i<argc; i++){
		if (send(sock, argv[i], strlen(argv[i]), 0) == -1) {
            perror("send");
            exit(1);
        }
        if (send(sock, ",", 1, 0) == -1) {
            perror("send");
            exit(1);
        }
        
	}
	
	if(shutdown(sock, SHUT_WR) < 0){
		perror("shutdown");
	}

	int bytes;
	string data = "";
    int done = 0;
    do {
        bytes = recv(sock, str, 100, 0);
        if (bytes <= 0) {
            if (bytes < 0) perror("recv");
            done = 1;
        }else {
            str[bytes] = 0;
            data += string(str);
        }
	} while (!done);
	
	close(sock);
	if(data.substr(0, 3) == "ERR"){
		printf("%s", data.c_str());
	}else if(strcmp(argv[1], "logs") == 0){
		char *cdata = new char[data.length()+1];
		strcpy (cdata, data.c_str());
  		vector<char *>args;
  		args.push_back(strtok (cdata,","));
  		int len = 0;								//length of non-NULL args
  		while(args.back() != NULL){
    		args.push_back(strtok (NULL, ","));
  		}
  		args.pop_back();
      printf("Printing last 10 lines\n");
  		for(int i=0; i<args.size(); i++){
  			printf("%s >>\n", args[i]);
        string STDOUT_logs = string(ROOT) + string(args[i]) + ".logs";
 			  string STDERR_logs = string(ROOT) + string(args[i]) + ".err";
        printf(" STDOUT(%s)>\n", STDOUT_logs.c_str());
 			  readFile(STDOUT_logs.c_str());
 			  printf("\n STDERR(%s)>\n", STDERR_logs.c_str());
 			  readFile(STDERR_logs.c_str());
 			  printf("\n\n");		
  		}
	}else printf("%s", data.c_str());
	

    return 0;
}
