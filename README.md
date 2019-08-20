# YALP
This is process manager which can manage process in linux. The basic job of this is to keep the process running in background even if crashes just like `systemd`.

NOTE: `UUID/id` refers to unique identifier assigned to process

### Installation
  * Run `make` to get `yapl` binary in bin folder

#### Commands
  * `yalp manage [-n identifier] command`
  
    Keep managing the process with identifier if specified otherwise a random idetifier assigned to process is returned
  * `yalp list`
  
    List identifiers for processes managed by yapl
  * `yalp logs [<id>|all]`
  
    Print last 10 lines of stdout & stderr
  * `yalp status [<id>|all]`
  
    Print identifier, PID, state, health statisitics mentioned below
  * `yalp start|stop|restart <id>`
  
    start|stop|restart a process identified by <id>
  * `yalp unmanage <id>`
       
    Stop managing the process identified by <id>
  * `yalp kill [signal] <id>`
       
    Send <signal> to the process identified by <id>

### Architecture

It is based on daemon-client model.
  * A single daemon process will handle managing, launching, stopping and restarting the processes.
      * Daemon uses a SIGCHLD signal handler to keep track of terminated children
        * It is used beacuse a single parent (daemon) makes its easy to keep track of terminated childs
        * Also the processes launched using daemon will be independent of terminal session and no SIGHUP will be sent to these processes causing termination or any other action.
      * Daemon uses 2 thread
        * 2 threads are required because SIGCHLD might interrupt if it is delievered while server is handling the client and may result in abnormal behaviour.
                * One thread runs a TCP server on port 31337 and service requests from client (SIGCHLD is blocked in this thread)
                * Other thread has SIGCHLD signal handler installed and it restarts the terminated processes on receiving the SIGCHLD signal.
                * The client program use TCP to send actions to perform to the daemon.
   * Choosing sockets over FIFOs or other IPC methods is just a personal preference.
      * Usually in client/server communication, it is required to use a special TOKEN (like <END> at the end of message) that confirm the end of message so that the other end won't block itself in a read call, since in this model client needs to send data once so use of use of the TOKEN can be eliminated using shutdown syscall which will terminate one half of connection and the other end won't get blocked.
   * Also if a process exits normally more than 10 times, it won't be started

##### Process
  This class stores information about the process like:
    * UUID (unique indentifier)
    * Arguments and location of executable
    * State
    * Other health statistics related variables

##### Logging
  * Logs of the yapl are stored on /tmp/logs
  * stdout and stderr of a process are stored in /tmp/<process-identifier>.logs (for stdout) and /tmp/<process-identifier>.err (for stderr)
    Before execing a process after fork, stdout and stderr mapped to above files by closing fd 1,2 and opening above files so process automatically write to the above files.
    `yapl logs` commands gives last 10 lines of logs

##### Health Statistics
  * No of times a process is restarted by yapl with exit status != 0 and exit status for every failure
  * Average running time of the process
  * Last duration for which process is running/stopped.

##### Error Handling
  * For each command, error like invalid arguments, insufficient args, invalid identifier are checked properly
  * While starting the process, errors like Binary doesn't exists, insufficient permission are checked and reported to user.
  * Errors if starting an already running process, stopping an inactive process, unmanaging running/inactive process are handles properly.
  * Basically I have make sure that you won't be able to break the tool by throwing random data to it.

##### Data Structures
  * Information about a process (state, args, no of failures) are stored using a process class object.
  * Tow maps, one maps process_identifier to its process object and other maps pid to process_identifier

##### Direcrtory Tree
```
├── bin
│   └── yapl                                    the yapl binary will be placed here on running `make`
├── makefile
├── README.md
├── src
│   ├── globals.h
│   ├── yclient.cpp                             code to talk to daemon
│   └── ydaemon.cpp                             code to manage processes
```
