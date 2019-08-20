#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <getopt.h>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <thread>
#include <string.h>
#include <map>

using namespace std;

string ROOT = "/tmp/";

//logging
string log_file_name = ROOT + "logs";
FILE *log_stream;

class process{
public:
	string state;
	char **args;
	int argc;
	int pid;
	string uuid;
	bool restart;
	int max_restarts;
	
	process(char *inp[], int inp_len, string uuid = ""){
		argc = inp_len;
		args = new char*[argc+1];
		for(int i=0; i<argc; i++){
			args[i] = new char[strlen(inp[i])];
			strcpy(args[i], inp[i]);
		}
		args[argc] = NULL;
		this->uuid = uuid.length() ? uuid : this->generateUUID();
		restart = true;
		max_restarts = 10;
	}
	
	string generateUUID(int len = 16){
		string CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

		string uuid = string(len,' ');
		int rnd = 0;
		int r = 0;

		for(int i=0;i<len;i++){
			if (rnd <= 0x02) {
				rnd = 0x2000000 + (rand() * 0x1000000) | 0;
			}
			rnd >>= 4;
			uuid[i] = CHARS[(i == 19) ? ((rnd & 0xf) & 0x3) | 0x8 : rnd & 0xf];
  		}
  		return uuid;
	}
		
};

map<string, process*> managed_processes;
map<int, string> pid_to_uuid;

void start_process(process *p){
	pid_t pid;
    if((pid = fork()) == 0){
    	// close all fds, though I need only 1,2 but this also closes parent log stream and sockets
    	for (int fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--) {
			close(fd);
		}

		// Reopen (fd = 1), (fd = 2)
		string plogs = ROOT + p->uuid + ".logs";
		int fd1 = open(plogs.c_str(), O_WRONLY | O_CREAT , S_IRWXU | S_IRWXG);
		int fd2 = open(plogs.c_str(), O_WRONLY | O_CREAT , S_IRWXU | S_IRWXG);
    	
        if(execve((p->args)[0], p->args, NULL) < 0)
        	perror("execve");
    }else{
        p->restart = 1;
    	p->pid = pid;
    	p->state = "active";
    	pid_to_uuid[p->pid] = p->uuid;
    }
}

void stop_process(process *p, int restart = 0){
	p->restart = restart;
    if(kill(p->pid, 9) == 0){
    	p->state = "stop";
    }else{
    	perror("kill");
    }
}

void handle_sigchld(int sig) {
  pid_t cid;
  while ((cid = waitpid((pid_t)(-1), 0, WNOHANG)) > 0) {
  	string cuuid = pid_to_uuid[cid];
	fprintf(log_stream, "SIGCLD::cid:%d, uuid:%s\n", cid, cuuid.c_str());
	pid_to_uuid.erase(cid); //this process will get a new pid
	
	process *p = managed_processes[cuuid];
	
	if(p->restart && p->max_restarts > 0){
		p->max_restarts -= 1;
		start_process(p);
    	pid_to_uuid[p->pid] = p->uuid;
    }else{
    	p->pid = -1;
    }
 }
}

string check_valid_args(char *args[], int n){
	if(n<=0) return "ERR: Too few arguments\n";
	string cur_uuid = string(args[0]);
    map<string, process*>::iterator it = managed_processes.find(cur_uuid);
    
    if(it == managed_processes.end()){
        fprintf(log_stream, "Invalid UUID\n");
        return "ERR: Invalid UUID\n";
    }
    return "";
}

string handle_manage(char *args[], int n){
	int i = 0;
	if(n <= 0){
		return "ERR: Too few arguments\n"; 
	}
	if(strcmp(args[0], "-n") == 0){
		if(n > 2 && args[1]){					//-n,name,executable = (>2)
			i = 2;
			n -= 2;
		}else return "ERR: Too few arguments\n";
	}
	    
    process *p;
    if(i==2) p = new process(&args[i], n, string(args[1]));
    else p = new process(&args[i], n);
    
    start_process(p);
	managed_processes[p->uuid] = p;
    fprintf(log_stream, "Process managed & started with UUID: %s\n", (p->uuid).c_str());
    return ("Process managed & started with UUID: "+p->uuid+"\n");
}

string handle_status(char *args[], int n){
	if(n <= 0){
		return "ERR: Too few arguments\n"; 
	}
	bool all = (strcmp(args[0], "all") == 0);
	if(!all && check_valid_args(args, n).length() != 0) return "ERR: Invalid UUID\n";
	
	string response = "Name" + string(20, ' ') + "State" + string(4, ' ') + "PID" + string(4, ' ') + "Process\n";
	map<string, process*>::iterator it;
    for(it=managed_processes.begin(); it != managed_processes.end(); it++){
    	if(!all && it->first != string(args[0])) continue;
    		process *p = it->second;
        	response += p->uuid + (((p->uuid).length() < 24) ? string(24-(p->uuid).length(), ' ') : "");
        	response += p->state + string(9-(p->state).length(), ' ');
        	response += to_string(p->pid) + string(7-(to_string(p->pid)).length(), ' ');
        	response += string(p->args[0]) + "\n";
    }
    return response;
}

string handle_logs(char *args[], int n){
	if(n <= 0){
		return "ERR: Too few arguments\n"; 
	}
	bool all = (strcmp(args[0], "all") == 0);
	if(!all && check_valid_args(args, n).length() != 0) return "ERR: Invalid UUID\n";
	
	string response = "";
	map<string, process*>::iterator it;
    for(it=managed_processes.begin(); it != managed_processes.end(); it++){
    	if(!all && it->first != string(args[0])) continue;
    		response += (it->first + ",");
    }
    return response;
}

void handle_client(){
	//char SOCK_PATH[] = "yapmat-conn";
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	int s, s2, len;
    
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( 5000 );
    if (bind(s, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("bind");
        exit(1);
    }

    if (listen(s, 5) == -1) {
        perror("listen");
        exit(1);
    }

    for(;;) {
        int done, n;
        fprintf(log_stream, "Waiting for yclient...\n");
        if ((s2 = accept(s, (struct sockaddr *)&address, &addrlen)) == -1) {
            perror("accept");
            exit(1);
        }

        fprintf(log_stream, "Connected.\n");
		string data = "";
        done = 0;
        do {
        	char str[100];
            n = recv(s2, str, 100, 0);
            if (n <= 0) {
                if (n < 0) perror("recv");
                done = 1;
                if(done) fprintf(log_stream, "Done\n");
            }else {
            	str[n] = 0;
            	data += string(str);
            	fprintf(log_stream, "RECV: %s\n", str);
            }
        } while (!done);
        
        char *cdata = new char[data.length()+1];
		strcpy (cdata, data.c_str());
		//fprintf(log_stream, cdata);
  		//fprintf (log_stream, "Splitting string \"%s\" into tokens:\n", cdata);
  		// take 30 as input from yclient
  		char *args[30];
  		args[0] = strtok (cdata,",");
  		int len = 0;								//length of non-NULL args
  		while(args[len] != NULL){
    		args[++len] = strtok (NULL, ",");
  		}
		string response = "";
		
        if(strcmp(args[0], "manage") == 0){
        	response = handle_manage(&args[1], len-1);
        	//response = new char[res.length()];
        	//strcpy(response, res.c_str());
        }else if(strcmp(args[0], "start") == 0){
        	//handle starting alsready running process
        	response = check_valid_args(&args[1], len-1);
        	if(response.length() == 0){
        		process *p = managed_processes[string(args[1])];
        		start_process(p);
        		response = "Process started with UUID: "+p->uuid+",\t PID: "+to_string(p->pid)+"\n";
        	}
        	fprintf(log_stream, response.c_str());
        }else if(strcmp(args[0], "stop") == 0){
        	//check if no uuid supplied
        	//handle stopping alsready stopped process
        	response = check_valid_args(&args[1], len-1);
        	if(response.length() == 0){
        		process *p = managed_processes[string(args[1])];
        		stop_process(p);
        		response = "Process stopped with UUID: "+p->uuid+"\n";
        	}
        	fprintf(log_stream, "%s", response.c_str());
        }else if(strcmp(args[0], "restart") == 0){
        	//handle running process vs handle stopped process
        	response = check_valid_args(&args[1], len-1);
        	if(response.length() == 0){
        		process *p = managed_processes[string(args[1])];
        		stop_process(p, 1);
        		response = "Process started with UUID: "+p->uuid+",\tnew PID: "+to_string(p->pid)+"\n";
        	}
        	fprintf(log_stream, response.c_str());
        }else if(strcmp(args[0], "unmanage") == 0){
        	response = check_valid_args(&args[1], len-1);
        	if(response.length() == 0){
        		process *p = managed_processes[string(args[1])];
        		stop_process(p);
        		while(p->pid != -1);											//wait until SIGCHLD gets executed
        		managed_processes.erase(p->uuid);
        		delete(p);
        		response = "Process unmanaged with UUID: "+p->uuid+"\n";
        	}
        	fprintf(log_stream, response.c_str());
        }else if(strcmp(args[0], "list") == 0){
        	response = "";
        	map<string, process*>::iterator it;
        	for(it=managed_processes.begin(); it != managed_processes.end(); it++){
        		response += (it->first + "\n");
        	}
        }else if(strcmp(args[0], "status") == 0){
        	response = handle_status(&args[1], len-1);
        }else if(strcmp(args[0], "logs") == 0){
        	response = handle_logs(&args[1], len-1);
        }
        
        if (send(s2, response.c_str(), (socklen_t)response.length(), 0) < 0) {
            perror("send");
        }
        
        if(close(s2) < 0){
			perror("close");
		}

    }
}

static void daemonize(){
	pid_t pid = 0;
	int fd;

	/* Fork off the parent process */
	pid = fork();

	/* An error occurred */
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	/* Success: Let the parent terminate */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* On success: The child process becomes session leader */
	if (setsid() < 0) {
		exit(EXIT_FAILURE);
	}

	/* Ignore signal sent from child to parent process */
	signal(SIGCHLD, SIG_IGN);

	/* Fork off for the second time*/
	pid = fork();

	/* An error occurred */
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	/* Success: Let the parent terminate */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Set new file permissions */
	umask(0);

	/* Change the working directory to the root directory */
	/* or another appropriated directory */
	chdir("/");

	/* Close all open file descriptors */
	for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--) {
		close(fd);
	}

	/* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
	stdin = fopen("/dev/null", "r");
	stdout = fopen("/dev/null", "w+");
	stderr = fopen(log_file_name.c_str(), "w+");
	
	//logging
	if (log_file_name.c_str() != NULL) {
		log_stream = fopen(log_file_name.c_str(), "w+");
		if (log_stream == NULL) {
			log_stream = stdout;
		}
		setbuf(log_stream, NULL);
	} else {
		log_stream = stdout;
	}
	
	fprintf(log_stream, "Daemon PID: %d\n", getpid());
}

int main(){
	daemonize();
	
	thread yclient(handle_client);

	//child sig handler
	struct sigaction sa;
	sa.sa_handler = &handle_sigchld;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;//SA_RESTART | SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, 0) == -1) {
  		perror(0);
 		exit(1);
	}
	yclient.join();
	return 0;
}
