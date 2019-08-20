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
#include <time.h>
#include <vector>

using namespace std;

string ROOT = "/tmp/";

//logging
string log_file_name = ROOT + "logs";
FILE *log_stream;

int listenfd, clientfd;

class process{
public:
	string state;
	char **args;
	int argc;
	int pid;
	string uuid;
	//stats related variables
	bool restart;
	int max_normal_restarts;
	int num_failed;
	vector<int>exit_status;
	long start_time, stop_time;
	int total_stops;
	double total_run_time;
	
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
		max_normal_restarts = 10;
		num_failed = 0;
		start_time = stop_time = -1;
		total_stops = 0;
		total_run_time = 0;
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

string start_process(process *p){
	pid_t pid;
	int pipe[2];					
	if (pipe2(pipe, O_CLOEXEC) < 0) 
        perror("pipe");

    if((pid = fork()) == 0){
    	// close all fds except pipe, though I need only 1,2 but this also closes parent log stream and sockets
    	close(1);
    	close(2);
    	close(listenfd);
    	close(clientfd);
		// Reopen (fd = 1), (fd = 2)
		string STDOUT_logs = ROOT + p->uuid + ".logs";
		string STDERR_logs = ROOT + p->uuid + ".err";
		int fd1 = open(STDOUT_logs.c_str(), O_WRONLY | O_CREAT , S_IRWXU | S_IRWXG);
		int fd2 = open(STDERR_logs.c_str(), O_WRONLY | O_CREAT , S_IRWXU | S_IRWXG);
    	setbuf(stderr, NULL);
        if(execve((p->args)[0], p->args, NULL) < 0){
        	perror("execve");
        	char *err = strerror(errno);
        	write(pipe[1], err, strlen(err));
        	exit(errno);
        }
    }else{
    	//verify execve is successfully executed;
    	char err[100];
    	close(pipe[1]);
    	int n;
    	if((n=read(pipe[0], err, 100)) > 0){
    		err[n] = 0;
    		fprintf(log_stream, "ERR: %s\n", err);
    		close(pipe[0]);
    		return ("ERR: "+string(err) + "\n");
    	}
    	p->restart = 1;
    	p->pid = pid;
    	p->state = "active";
    	pid_to_uuid[p->pid] = p->uuid;
    	p->start_time = time(NULL);
    	fprintf(log_stream, "Process started with pid:%d, uuid:%s\n", pid, (p->uuid).c_str());
    	return "";
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
  int status;
  while ((cid = waitpid((pid_t)(-1), &status, WNOHANG)) > 0) {
  	string cuuid = pid_to_uuid[cid];
  	if(cuuid == "") return;
	fprintf(log_stream, "SIGCLD:: pid:%d, uuid:%s, exit status:%d\n", cid, cuuid.c_str(), status);
	pid_to_uuid.erase(cid); //this process will get a new pid
	
	process *p = managed_processes[cuuid];
	p->stop_time = time(NULL);
	p->total_stops += 1;
	p->total_run_time += (p->stop_time - p->start_time);
	if(p->restart && p->max_normal_restarts > 0){
		if(status == 0) p->max_normal_restarts -= 1;
		if(p->state == "active" && status != 0){
			p->num_failed += 1;
			(p->exit_status).push_back(status);
		}
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
    if(i==2){
    	map<string, process*>::iterator it = managed_processes.find(string(args[1]));
    
    	if(it != managed_processes.end()){
        	fprintf(log_stream, "Duplicate UUID\n");
        	return "ERR: Duplicate UUID\n";
    	}
    	p = new process(&args[i], n, string(args[1]));
    }
    else p = new process(&args[i], n);
    
    string response = start_process(p);
    if(response.length() != 0) return response; //unable to start process exec error
 
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
	
	string response = "";
	map<string, process*>::iterator it;
    for(it=managed_processes.begin(); it != managed_processes.end(); it++){
    	if(!all && it->first != string(args[0])) continue;
    		process *p = it->second;
    		response += p->uuid + ">\n";
    		response += "  State: " + p->state + "\n";
    		if (p->pid != -1) response += "  PID: " + to_string(p->pid) + "\n";
    		response += "  Restarts: " + to_string(p->num_failed) + (((p->exit_status).size() > 0) ? (" and last exited with status: " + to_string((p->exit_status).back())) : "")+"\n";
        	if (p->state == "active"){
        		response += "  Active for " + to_string(time(NULL) - p->start_time) + " sec\n";
        	}else{
        		response += "  Stopped for " + to_string(time(NULL) - p->stop_time) + " sec\n";
        	}
        	if(p->total_stops > 0){
        		double av_time = p->total_run_time/p->total_stops;
        		response += "  Avg Active Time: " + to_string(av_time) + "\n";
        	}
        	response += "  Command: " + string(p->args[0]) + "\n";
    }
    if(response.length() == 0) response = "Nothing to show :(\n";
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
    if(response.length() == 0) response = "Nothing to show :(\n";
    return response;
}

void handle_client(){
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	int len;
    
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( 31337 );
    if (bind(listenfd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("bind");
        exit(1);
    }

    if (listen(listenfd, 5) == -1) {
        perror("listen");
        exit(1);
    }

    for(;;) {
        int done, n;
        fprintf(log_stream, "Waiting for yclient...\n");
        if ((clientfd = accept(listenfd, (struct sockaddr *)&address, &addrlen)) == -1) {
            perror("accept");
            exit(1);
        }

		string data = "";
        done = 0;
        do {
        	char str[100];
            n = recv(clientfd, str, 100, 0);
            if (n <= 0) {
                if (n < 0) perror("recv");
                done = 1;
            }else {
            	str[n] = 0;
            	data += string(str);
            }
        } while (!done);
        
        char *cdata = new char[data.length()+1];
		strcpy (cdata, data.c_str());
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
        }else if(strcmp(args[0], "start") == 0){
        	//handle starting alsready running process
        	response = check_valid_args(&args[1], len-1);
        	if(response.length() == 0){
        		process *p = managed_processes[string(args[1])];
        		if(p->state == "stop"){
        			start_process(p);
        			response = "Process started with UUID: "+p->uuid+"\n";
        		}else response = "Process with UUID: "+p->uuid+" is already running\n";
        	}
        	fprintf(log_stream, "%s", response.c_str());
        }else if(strcmp(args[0], "stop") == 0){
        	//handle stopping alsready stopped process
        	response = check_valid_args(&args[1], len-1);
        	if(response.length() == 0){
        		process *p = managed_processes[string(args[1])];
        		if(p->state == "active"){
        			stop_process(p);
        			response = "Process stopped with UUID: "+p->uuid+"\n";
        		}else response = "Process with UUID: "+p->uuid+" is already stopped\n";
        	}
        	fprintf(log_stream, "%s", response.c_str());
        }else if(strcmp(args[0], "restart") == 0){
        	//handle running process vs handle stopped process
        	response = check_valid_args(&args[1], len-1);
        	if(response.length() == 0){
        		process *p = managed_processes[string(args[1])];
        		if(p->state == "active")
        			stop_process(p, 1);
        		else start_process(p);
        		response = "Process started with UUID: "+p->uuid+",\tnew PID: "+to_string(p->pid)+"\n";
        	}
        	fprintf(log_stream, "%s", response.c_str());
        }else if(strcmp(args[0], "unmanage") == 0){
        	response = check_valid_args(&args[1], len-1);
        	if(response.length() == 0){
        		process *p = managed_processes[string(args[1])];
        		if(p->state == "active")
        			stop_process(p);
        		while(p->pid != -1);											//wait until SIGCHLD gets executed
        		managed_processes.erase(p->uuid);
        		delete(p);
        		response = "Process unmanaged with UUID: "+p->uuid+"\n";
        	}
        	fprintf(log_stream, "%s", response.c_str());
        }else if(strcmp(args[0], "list") == 0){
        	response = "";
        	map<string, process*>::iterator it;
        	for(it=managed_processes.begin(); it != managed_processes.end(); it++){
        		response += (it->first + "\n");
        	}
        	response = "Nothing to show :(\n";
        }else if(strcmp(args[0], "status") == 0){
        	response = handle_status(&args[1], len-1);
        }else if(strcmp(args[0], "logs") == 0){
        	response = handle_logs(&args[1], len-1);
        }else response = "ERR: Invalid Arguments\n";
        
        if (send(clientfd, response.c_str(), (socklen_t)response.length(), 0) < 0) {
            perror("send");
        }
        
        if(close(clientfd) < 0){
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

void init_ydaemon(){
	daemonize();
	
	thread yclient(handle_client);

	//SIGCHLD sig handler
	struct sigaction sa;
	sa.sa_handler = &handle_sigchld;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGCHLD, &sa, 0) == -1) {
  		perror(0);
 		exit(1);
	}
	yclient.join();
}

int main(){
	init_ydaemon();
	return 0;
}
