/*
 * tsh - A tiny shell program with job control
 *
 * Each tag in the comment of the functions indicates the job done
 * <Provided> = given in default within the assignment
 * <Modified> = was given, but few changes exist in the code
 * <Created> = newly written from scratch
 * 
 * The comments for <Provided> functions are not changed
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#ifdef DEBUG
#define DPRINT(...) fprintf( stderr, __VA_ARGS__ )
#else
#define DPRINT(...) do{ } while ( 0 )
#endif

/* Misc manifest constants */
#define MAXLINE    1024   /* max line size */
#define MAXARGS     128   /* max args on a shell line */
#define MAXCMDS     8     /* max cmds on a shell line */
#define MAXJOBS      16   /* max jobs at any point in time */
#define MAXJID    1<<16   /* max job ID */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

#define PIPE_IN 0
#define PIPE_OUT 1

/*
 * Jobs states: FG (foreground), BG (background), ST (stopped)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

/* Global variables */
extern char **environ;      /* defined in libc */
char prompt[] = "tsh> ";    /* shell line prompt (DO NOT CHANGE) */
int verbose = 0;            /* if true, print additional output */
int nextjid = 1;            /* next job ID to allocate */
char sbuf[MAXLINE];         /* for composing sprintf messages */

struct job_t {              /* The job struct */
    pid_t pid;              /* job PID */
    int jid;                /* job ID [1, 2, ...] */
    int state;              /* UNDEF, BG, FG, or ST */
    char shline[MAXLINE];  /* shell line */
};
struct job_t jobs[MAXJOBS];

struct cmd_t {
    int argc;
    char *argv[MAXARGS];
    int is_head;
    int bg;
    int pid;
    int pipe[2];
    struct cmd_t *next;
    char shline[MAXLINE];
};
typedef struct cmd_t cmd_t;

/* Function headers */
cmd_t *alloc_cmd(void);
void free_cmd(cmd_t *);

void eval(char *shline);
int builtin_cmd(char **argv);
void do_bgfg(char **argv);
void waitfg(pid_t pid);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);

int parseline(const char *shline, cmd_t *cmd);
void sigquit_handler(int sig);

void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs);
int addjob(struct job_t *jobs, pid_t pid, int state, char *shline);
int deletejob(struct job_t *jobs, pid_t pid);
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid);
int pid2jid(pid_t pid);
void listjobs(struct job_t *jobs);

void usage(void);
void unix_error(char *msg);
void app_error(char *msg);
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);

void handle_pipe_child(cmd_t *cmd);
void handle_pipe_parent(cmd_t *cmd);

/*
 * <Provided>
 * main - The shell's main routine
 */
int main(int argc, char **argv)
{
    char c;
    char shline[MAXLINE];
    int emit_prompt = 1;

    if(dup2(1, 2) < 0) unix_error("dup2 error");

    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
            case 'h':             
                usage();
            break;
            case 'v':             
                verbose = 1;
            break;
            case 'p':             
                emit_prompt = 0;  
            break;
            default:
                usage();
	      }
    }

    Signal(SIGINT,  sigint_handler);
    Signal(SIGTSTP, sigtstp_handler);
    Signal(SIGCHLD, sigchld_handler); 

    initjobs(jobs);

    while (1) {
      
      if (emit_prompt) {
          printf("%s", prompt);
          fflush(stdout);
      }
      if ((fgets(shline, MAXLINE, stdin) == NULL) && ferror(stdin))
          app_error("fgets error");
      if (feof(stdin)) {
          fflush(stdout);
          exit(0);
      }

      eval(shline);
      fflush(stdout);
      fflush(stdout);
    }

    exit(0);
}

/*
 * <Developed>
 * handle_pipe_child - Redirect the input/output of the child process for pipe operation
 */
void handle_pipe_child(cmd_t *cmd) {
    if(cmd->pipe[PIPE_IN] != 0) if(dup2(cmd->pipe[PIPE_IN], STDIN_FILENO) < 0) unix_error("dup2 error");
    if(cmd->pipe[PIPE_OUT] != 0) if(dup2(cmd->pipe[PIPE_OUT], STDOUT_FILENO) < 0) unix_error("dup2 error");
}

/*
 * <Developed>
 * handle_pipe_parent - Close the file descriptors used for pipe for parent process, as it is not used
 */
void handle_pipe_parent(cmd_t *cmd) {
    if(cmd->pipe[PIPE_IN] != 0) if(close(cmd->pipe[PIPE_IN]) < 0) unix_error("close error");
    if(cmd->pipe[PIPE_OUT] != 0) if(close(cmd->pipe[PIPE_OUT]) < 0) unix_error("close eror");
}

/*
 * <Developed>
 * eval - Evaluate the shell line that the user has just typed in
 *
 * The given shell command string is first split according to the delimeter "|".
 * At the same time, each split string is parsed to cmd_t structure by parseline().
 * For pipe operation, if there are multiple cmd_t's made per shline, then new
 * file descriptors are opened for input/output redirection, also saved in the 
 * cmd_t structure.
 * 
 * Each cmd_t structure made is then actually executed. First, the given command 
 * is checked if it is a built-in command. If so, the builtin_cmd() exectues the
 * command immediately. If not a built-in command, the command is executed by 
 * making a new child process using fork(). Before calling fork(), the SIGCHLD
 * signal is blocked by sigprocmask for preventing concurrency bugs.
 * 
 * After fork() is returned, for the parent process, first the unused file
 * descriptors made for pipe operation are close. Then whether the command is
 * meant to be run in the foreground or background is checked, adding the job
 * according to it. After adding the job, SIGCHLD is unblocked.
 * 
 * For the child process, the group pid is changed for preventing unwanted signals
 * from the parent process. The SIGCHLD signal is unblocked, and the input/output
 * is redirected for pipe operation. Then the actual command is exectued using
 * execve(), and lastly the file descriptors used for pipe operation are closed.
*/
void eval(char *shline)
{
    char *env[] = {NULL};
    // split shline according to "|"
    const char delim[] = "|";
    int cmd_cnt = 0;
    cmd_t **cmds = malloc(sizeof(cmd_t*) * MAXCMDS);
    char* single_sh = strtok(shline, delim);
    while(single_sh != NULL) {
        cmds[cmd_cnt] = alloc_cmd();
        parseline(single_sh, cmds[cmd_cnt]);
        single_sh = strtok(NULL, delim);
        cmd_cnt++;       
    }
    // open new file descriptors for each pipe operation
    for(int i = 1; i < cmd_cnt; i++) {
        int pipe_fd[2];
        if(pipe(pipe_fd) < 0) unix_error("pipe error");
        cmds[i - 1]->next = cmds[i];
        cmds[i - 1]->pipe[PIPE_OUT] = pipe_fd[PIPE_OUT];
        cmds[i]->pipe[PIPE_IN] = pipe_fd[PIPE_IN];
    }
    // execute command
    for(int i = 0; i < cmd_cnt; i++){
        cmd_t *cmd = cmds[i];
        // check if built_in
        if(!builtin_cmd(cmd->argv)) {    
            sigset_t mask;     
            if(sigemptyset(&mask) < 0) unix_error("sigemptyset error");
            if(sigaddset(&mask, SIGCHLD) < 0) unix_error("sigaddset error");
            if(sigprocmask(SIG_BLOCK, &mask, NULL) < 0) unix_error("sigprocmask error");
            pid_t pid = fork();
            if(pid < 0) unix_error("fork error");
            // child process
            if(pid == 0) {
                if(setpgid(0, 0) < 0) unix_error("setpgid error");
                if(sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0) unix_error("sigprocmask error");
                handle_pipe_child(cmd);
                if(execve(cmd->argv[0], cmd->argv, env) < 0) {
                    printf("%s: Command not found\n", cmd->argv[0]);
                    exit(0);
                }
                if(cmd->pipe[PIPE_OUT] != 0) if(close(cmd->pipe[PIPE_OUT]) < 0) unix_error("close error");
                if(cmd->pipe[PIPE_IN] != 0) if(close(cmd->pipe[PIPE_IN]) < 0) unix_error("close error");
            }
            // parent process
            else {
                handle_pipe_parent(cmd);
                if(!cmd->bg) {
                    addjob(jobs, pid, FG, cmd->shline);
                    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0) unix_error("sigprocmask error");
                    waitfg(pid);
                }
                else {
                    addjob(jobs, pid, BG, cmd->shline);
                    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0) unix_error("sigprocmask error");
                    printf("[%d] (%d) %s", pid2jid(pid), pid, cmd->shline);
                }
            }
        }
    }
    // free all necessary malloc
    for(int i = 0; i < cmd_cnt; i++) free_cmd(cmds[i]);
    free(cmds);
    return;
}

/*
 * <Provided>
 * parseline - Parse the shell line and build the command structure.
 *
 * Characters enclosed in single quotes are treated as a single
 * argument.  Return true if the user has requested a BG job, false if
 * the user has requested a FG job.
 */
int parseline(const char *shline, cmd_t *cmd) {
    char *buf_base = NULL;
    char *buf = NULL;
    char *delim;                /* points to first space delimiter */

    buf = buf_base = malloc(MAXLINE);
    if (!buf_base) {
        unix_error("malloc error");
        exit(-1);
    }

    strcpy(buf, shline);
    buf[strlen(buf)-1] = ' ';  /* replace trailing '\n' with space */
    while (*buf && (*buf == ' ')) buf++; /* ignore leading spaces */

    cmd->argc = 0;
    if (*buf == '\'') {
        buf++;  
        delim = strchr(buf, '\'');
    }
    else {
	      delim = strchr(buf, ' ');
    }

    while (delim) {
	      cmd->argv[cmd->argc] = buf;
        cmd->argc = cmd->argc + 1;
        *delim = '\0';
        buf = delim + 1;
        while (*buf && (*buf == ' ')) buf++;/* ignore spaces */
        if (*buf == '|') {
            buf++;
            break;
        }
        if (*buf == '\'') {
            buf++;
            delim = strchr(buf, '\'');
        }
        else {
            delim = strchr(buf, ' ');
        }
    }
    cmd->argv[cmd->argc] = NULL;

    if (cmd->argc != 0) {
        /* should the job run in the background? */
        cmd->bg = 0;
        if (cmd->argv[cmd->argc-1][0] == '&') {
            cmd->bg = 1;
        }

        if (cmd->bg != 0) {
            cmd->argc = cmd->argc - 1;
            cmd->argv[cmd->argc] = NULL;

        }
    }

    int this_shline_len = (int)(buf-buf_base);

    strncpy(cmd->shline, shline, this_shline_len);
    cmd->shline[this_shline_len] = '\0';

    return this_shline_len;
}

/*
 * <Developed>
 * builtin_cmd - if the user has typed a built-in command then execute it immediately.
 * 
 * Built-in commands in this assignment are "quit", "jobs", "bg" and "fg". 
 * The "quit" command triggers exit() immediately. The "jobs", "bg", or "fg"
 * commands are all done by other user-defined functions. If the given 
 * command was a built-in command, the function returns 1, 0 for else.
 */
int builtin_cmd(char **argv)
{
    char * cmd = argv[0];
    // quit
    if(!strcmp(cmd, "quit")) {
        exit(0);
        return 1;
    }
    // jobs
    else if(!strcmp(cmd, "jobs")) {
        listjobs(jobs);
        return 1;
    }
    // bg and fg
    else if(!strcmp(cmd, "bg") || !strcmp(cmd, "fg")){
        do_bgfg(argv);
        return 1;
    }
    // not built-in command
    return 0;
}

/*
 * <Developed>
 * do_bgfg - Execute the builtin bg and fg commands
 * 
 * First checks the validity of the command. If there is either no process/job 
 * id given, or non-existing process/job id given, the command is not executed.
 * For a valid command, the job's changed to FG or BG according to the command,
 * and is SIGCONT signal is given to the job's process. If the job is to run in
 * the foreground, the parent process waits for the job to end.
 */
void do_bgfg(char **argv)
{
    char *job_name = argv[1];
    // check if no job or process is given
    if(job_name == NULL) {
        printf("%s command requires PID or %%jobid argument\n", argv[0]);
        return;
    }
    char * temp = job_name;
    if(!strncmp(job_name, "%%", 1)) temp++;
    if(!isdigit((unsigned char)*temp)) {
        printf("%s: argument must be a PID or %%jobid\n", argv[0]);
        temp++;
        return;
    }
    // check if wrong job or process is given
    struct job_t *job;
    if(!strncmp(job_name, "%%", 1)) {
        job = getjobjid(jobs, atoi(job_name + 1));
        if(job == NULL) {
            printf("%s: No such job\n", job_name);
            return;
        }
    }
    else {
        job = getjobpid(jobs, atoi(job_name));
        if(job == NULL) {
            printf("(%s): No such process\n", job_name);
            return;
        }
    }
    // fg
    if(!strcmp(argv[0], "fg")) job->state = FG;
    // bg
    else {
        printf("[%d] (%d) %s", job->jid, job->pid, job->shline);
        job->state = BG;
    }
    // continue the job
    if(kill(-(job->pid), SIGCONT) < 0) unix_error("kill error");
    if(!strcmp(argv[0], "fg")) waitfg(job->pid);
    return;
}

/*
 * <Developed>
 * waitfg - Block until process pid is no longer the foreground process
 * 
 * Gets the job pointer and keeps checking if the job's state becomes undefined
 * or stopped.
 */
void waitfg(pid_t pid)
{
    struct job_t *job = getjobpid(jobs, pid);
    while(job->state != UNDEF && job->state != ST) sleep(1);
    return;
}

/*****************
 * Signal handlers
 *****************/

/*
 * <Developed>
 * sigchld_handler - Catch SIGCHLD signal sent from the kernel whenever a child job terminates or stops, and reaps all available zombie children
 * 
 * Using waitpid(), keep checks if there is a child process to be reaped. If a pid is returned,
 * checks if the child process was either stopped or terminated. If stopped, the process's state
 * is changed to stopped. If terminated, the process is deleted from job list.
 */
void sigchld_handler(int sig)
{
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG | WUNTRACED);
    while(pid > 0) {
        // child stopped
        if(WIFSTOPPED(status)) {
            getjobpid(jobs, pid)->state = ST;
            printf("Job [%d] (%d) stopped by signal %d\n", pid2jid(pid), pid, SIGTSTP);
        }
        // child terminated
        else if(WIFSIGNALED(status) && WTERMSIG(status) > 0) printf("Job [%d] (%d) terminated by signal %d\n", pid2jid(pid), pid, SIGINT);
        if(getjobpid(jobs, pid)->state != ST) deletejob(jobs, pid);
        pid = waitpid(-1, &status, WNOHANG | WUNTRACED);
    }
    return;
}

/*
 * <Developed>
 * sigint_handler - Catch SIGINT signal sent to shell when ctrl-c is typed and terminate the foreground job.
 * 
 * Checks the foreground job, and if a job exists, and send SIGTINT signal to the whole group by kill().
 */
void sigint_handler(int sig)
{
    pid_t pid = fgpid(jobs);
    if(pid == 0) return;
    if(kill(-pid, SIGINT) < 0) unix_error("kill error");
    return;
}

/*
 * <Developed>
 * sigtstp_handler - Catch SIGTSTP signal sent to shell when ctrl-z is typed and suspend the foreground job.
 * 
 * Checks the foreground job, and if a job exists, change the state of the job into
 * stopped, and send SIGTSTP signal to the whole group by kill().
 */
void sigtstp_handler(int sig)
{
    pid_t pid = fgpid(jobs);
    if(pid == 0) return;
    getjobpid(jobs, pid)->state = ST;
    if(kill(-pid, SIGTSTP) < 0) unix_error("kill error");
    return;
}

/*********************
 * End signal handlers
 *********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* <Provided> clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job) {
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->shline[0] = '\0';
}

/* <Provided> initjobs - Initialize the job list */
void initjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++) clearjob(&jobs[i]);
}

/* <Provided> maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs)
{
    int i, max=0;

    for (i = 0; i < MAXJOBS; i++)
	  if (jobs[i].jid > max) max = jobs[i].jid;
    return max;
}

/* <Provided> addjob - Add a job to the job list */
int addjob(struct job_t *jobs, pid_t pid, int state, char *shline)
{
    int i;

    if (pid < 1) return 0;

    for (i = 0; i < MAXJOBS; i++) {
	      if (jobs[i].pid == 0) {
            jobs[i].pid = pid;
            jobs[i].state = state;
            jobs[i].jid = nextjid++;
            if (nextjid > MAXJOBS) nextjid = 1;
	          strcpy(jobs[i].shline, shline);
  	        if(verbose) printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].shline);
            return 1;
	      }
    }
    printf("Tried to create too many jobs\n");
    return 0;
}

/* <Provided> deletejob - Delete a job whose PID=pid from the job list */
int deletejob(struct job_t *jobs, pid_t pid)
{
    int i;

    if (pid < 1) return 0;

    for (i = 0; i < MAXJOBS; i++) {
	      if (jobs[i].pid == pid) {
            clearjob(&jobs[i]);
            nextjid = maxjid(jobs)+1;
            return 1;
        }
    }
    return 0;
}

/* <Provided> fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs) {
    int i;
    for (i = 0; i < MAXJOBS; i++) if (jobs[i].state == FG) return jobs[i].pid;
    return 0;
}

/* <Provided> getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid) {
    int i;
    if (pid < 1) return NULL;
    for (i = 0; i < MAXJOBS; i++) if (jobs[i].pid == pid) return &jobs[i];
    return NULL;
}

/* <Provided> getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid)
{
    int i;
    if (jid < 1) return NULL;
    for (i = 0; i < MAXJOBS; i++) if (jobs[i].jid == jid) return &jobs[i];
    return NULL;
}

/* <Provided> pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid)
{
    int i;

    if (pid < 1) return 0;
    for (i = 0; i < MAXJOBS; i++) if (jobs[i].pid == pid) return jobs[i].jid;
    return 0;
}

/* 
 * <Modified> 
 * listjobs - Print the job list 
 * 
 * The default listjobs printed every single job, including
 * the jobs running in the foreground as well, which is not
 * intended in this assignment
 */
void listjobs(struct job_t *jobs)
{
    int i;
    for (i = 0; i < MAXJOBS; i++) {
	      if (jobs[i].pid != 0) {
            if(jobs[i].state == FG) continue;
            printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
            switch (jobs[i].state) {
            case BG:
                printf("Running ");
                break;
            case ST:
                printf("Stopped ");
                break;
            default:
                printf("listjobs: Internal error: job[%d].state=%d ",
                i, jobs[i].state);
            }
            printf("%s", jobs[i].shline);
	      }
    }
}
/******************************
 * end job list helper routines
 ******************************/


/***********************
 * Other helper routines
 ***********************/

/*
 * <Provided>
 * usage - print a help message
 */
void usage(void)
{
    printf("Usage: shell [-hvp]\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("   -p   do not emit a command prompt\n");
    exit(1);
}

/*
 * <Provided>
 * unix_error - unix-style error routine */
void unix_error(char *msg)
{
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

/*
 * <Provided>
 * app_error - application-style error routine
 */
void app_error(char *msg)
{
    fprintf(stdout, "%s\n", msg);
    exit(1);
}

/*
 * <Provided>
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler)
{
    struct sigaction action, old_action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;

    if (sigaction(signum, &action, &old_action) < 0) unix_error("Signal error");
    return (old_action.sa_handler);
}

/*
 * <Provided>
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 */
void sigquit_handler(int sig)
{
    printf("Terminating after receipt of SIGQUIT signal\n");
    exit(1);
}


/*
 * <Provided>
 * alloc_cmd - Dynamically allocate the command structure
 */
cmd_t *alloc_cmd(void) {
    cmd_t *cmd = malloc(sizeof(cmd_t));
    return cmd;
}

/*
 * <Developed>
 * free_cmd - Free the command structure
 */
void free_cmd(cmd_t *c) {
    free(c);
}

