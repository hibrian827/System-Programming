/*
 * tsh - A tiny shell program with job control
 *
 * <Put your name and login ID here>
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

/* #define DEBUG */

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
struct job_t jobs[MAXJOBS]; /* The job list */
/* End global variables */


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

cmd_t *alloc_cmd(void);
void free_cmd(cmd_t *);
void print_cmd(cmd_t *);


/* Function prototypes */

/* Here are the functions that you will implement */
void eval(char *shline);
int builtin_cmd(char **argv);
void do_bgfg(char **argv);
void waitfg(pid_t pid);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);

/* Here are helper routines that we've provided for you */
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
 * main - The shell's main routine
 */
int main(int argc, char **argv)
{
    char c;
    char shline[MAXLINE];
    int emit_prompt = 1; /* emit prompt (default) */

    /* Redirect stderr to stdout (so that driver will get all output
     * on the pipe connected to stdout) */
    dup2(1, 2);

    /* Parse the shell line */
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
            case 'h':             /* print help message */
                usage();
            break;
            case 'v':             /* emit additional diagnostic info */
                verbose = 1;
            break;
            case 'p':             /* don't print a prompt */
                emit_prompt = 0;  /* handy for automatic testing */
            break;
            default:
                usage();
	      }
    }

    /* Install the signal handlers */

    /* These are the ones you will need to implement */
    Signal(SIGINT,  sigint_handler);   /* ctrl-c */
    Signal(SIGTSTP, sigtstp_handler);  /* ctrl-z */
    Signal(SIGCHLD, sigchld_handler);  /* Terminated or stopped child */

    /* Initialize the job list */
    initjobs(jobs);

    /* Execute the shell's read/eval loop */
    while (1) {

      /* Read shell line */
      if (emit_prompt) {
          printf("%s", prompt);
          fflush(stdout);
      }
      if ((fgets(shline, MAXLINE, stdin) == NULL) && ferror(stdin))
          app_error("fgets error");
      if (feof(stdin)) { /* End of file (ctrl-d) */
          fflush(stdout);
          exit(0);
      }

      /* Evaluate the shell line */
      eval(shline);
      fflush(stdout);
      fflush(stdout);
    }

    exit(0); /* control never reaches here */
}

void handle_cmd(cmd_t *cmd) {
    pid_t pid;           /* process id */
    sigset_t mask;       /* signal mask */
    char **argv = cmd->argv;
    int bg = cmd->bg;

    // https://github.com/robotmlg/simple-shell/blob/master/shell.c
    if (argv[0] == NULL) return;   /* ignore empty lines */

    if (builtin_cmd(argv)) {
        return;
    }

    /*
     * This is a little tricky. Block SIGCHLD, SIGINT, and SIGTSTP
     * signals until we can add the job to the job list. This
     * eliminates some nasty races between adding a job to the job
     * list and the arrival of SIGCHLD, SIGINT, and SIGTSTP signals.
     */

    if (sigemptyset(&mask) < 0)
        unix_error("sigemptyset error");
    if (sigaddset(&mask, SIGCHLD))
        unix_error("sigaddset error");
    if (sigaddset(&mask, SIGINT))
        unix_error("sigaddset error");
    if (sigaddset(&mask, SIGTSTP))
        unix_error("sigaddset error");
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        unix_error("sigprocmask error");

    /* Create a child process */
    if ((pid = fork()) < 0)
        unix_error("fork error");

    if (pid == 0) {
        /* Child process  */
        /* Child unblocks signals */
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        /* Each new job must get a new process group ID
           so that the kernel doesn't send ctrl-c and ctrl-z
           signals to all of the shell's jobs */
        if (setpgid(0, 0) < 0)
            unix_error("setpgid error");


        handle_pipe_child(cmd);

        /* Now load and run the program in the new job */
        if (execve(argv[0], argv, environ) < 0) {
            printf("%s: Command not found\n", argv[0]);
            exit(0);
        }
    } else {
        /* Parent process */
        /* Parent adds the job, and then unblocks signals so that
           the signals handlers can run again */
        addjob(jobs, pid, (bg == 1 ? BG : FG), cmd->shline);
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        handle_pipe_parent(cmd);

        if (!bg)
            waitfg(pid);
        else
            printf("[%d] (%d) %s", pid2jid(pid), pid, cmd->shline);

    }
}

void handle_pipe_child(cmd_t *cmd) {
    if(cmd->pipe[PIPE_IN] != 0) dup2(cmd->pipe[PIPE_IN], STDIN_FILENO);
    if(cmd->pipe[PIPE_OUT] != 0) dup2(cmd->pipe[PIPE_OUT], STDOUT_FILENO);
}

void handle_pipe_parent(cmd_t *cmd) {
    if(cmd->pipe[PIPE_IN] != 0) close(cmd->pipe[PIPE_IN]);
    if(cmd->pipe[PIPE_OUT] != 0) close(cmd->pipe[PIPE_OUT]);
}

/*
 * eval - Evaluate the shell line that the user has just typed in
 *
 * First, parse the shell line into a list of commands. Next, for each
 * command, if the user has requested a built-in command (quit, jobs,
 * bg or fg) then execute it immediately. Otherwise, fork a child
 * process and run the job in the context of the child. If the job is
 * running in the foreground, wait for it to terminate and then
 * return. If the user specified the pipe, properly setup the pipe
 * between two processes. Note: each child process must have a unique
 * process group ID so that our background children don't receive
 * SIGINT (SIGTSTP) from the kernel when we type ctrl-c (ctrl-z) at
 * the keyboard.
*/
void eval(char *shline)
{
    char *env[] = {NULL};
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
    for(int i = 1; i < cmd_cnt; i++) {
        int pipe_fd[2];
        if(pipe(pipe_fd) < 0) unix_error("pipe error");
        cmds[i - 1]->next = cmds[i];
        cmds[i - 1]->pipe[PIPE_OUT] = pipe_fd[PIPE_OUT];
        cmds[i]->pipe[PIPE_IN] = pipe_fd[PIPE_IN];
    }
    for(int i = 0; i < cmd_cnt; i++){
        cmd_t *cmd = cmds[i];
        // print_cmd(cmd);
        if(!builtin_cmd(cmd->argv)) {    
            sigset_t mask;     
            if(sigemptyset(&mask) < 0) unix_error("sigemptyset error");
            if(sigaddset(&mask, SIGCHLD)) unix_error("sigaddset error");
            if(sigprocmask(SIG_BLOCK, &mask, NULL) < 0) unix_error("sigprocmask error");
            pid_t pid = fork();
            if(pid < 0) unix_error("fork error");
            if(pid == 0) {
                if(setpgid(0, 0) < 0) printf("setpgid error");
                if(sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0) unix_error("sigprocmask error");
                handle_pipe_child(cmd);
                if(execve(cmd->argv[0], cmd->argv, env) < 0) {
                    printf("%s: Command not found\n", cmd->argv[0]);
                    exit(0);
                }
                if(cmd->pipe[PIPE_OUT] != 0) close(cmd->pipe[PIPE_OUT]);
                if(cmd->pipe[PIPE_IN] != 0) close(cmd->pipe[PIPE_IN]);
            }
            else {
                if (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0) unix_error("sigprocmask error");
                handle_pipe_parent(cmd);
                if(!cmd->bg) {
                    addjob(jobs, pid, FG, cmd->shline);
                    waitfg(pid);
                }
                else {
                    addjob(jobs, pid, BG, cmd->shline);
                    printf("[%d] (%d) %s", pid2jid(pid), pid, cmd->shline);
                }
            }
        }
    }
    for(int i = 0; i < cmd_cnt; i++) free_cmd(cmds[i]);
    free(cmds);
    return;
}

/*
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
 * builtin_cmd - If the user has typed a built-in command then execute
 *    it immediately.
 */
int builtin_cmd(char **argv)
{
    char * cmd = argv[0];
    if(!strcmp(cmd, "quit")) {
        exit(0);
        return 1;
    }
    else if(!strcmp(cmd, "jobs")) {
        listjobs(jobs);
        return 1;
    }
    else if(!strcmp(cmd, "bg") || !strcmp(cmd, "fg")){
        do_bgfg(argv);
        return 1;
    }
    return 0;     /* not a builtin command */
}

/*
 * do_bgfg - Execute the builtin bg and fg commands
 */
void do_bgfg(char **argv)
{
    char *job_name = argv[1];
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
    if(!strcmp(argv[0], "fg")) {
        job->state = FG;
    }
    // bg
    else {
        printf("[%d] (%d) %s", job->jid, job->pid, job->shline);
        job->state = BG;
    }
    if(kill(-(job->pid), SIGCONT) < 0) unix_error("kill error");
    if(!strcmp(argv[0], "fg")) waitfg(job->pid);
    return;
}

/*
 * waitfg - Block until process pid is no longer the foreground process
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
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.
 */
void sigchld_handler(int sig)
{
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG | WUNTRACED);
    while(pid > 0) {
        if(WIFSTOPPED(status)) {
            getjobpid(jobs, pid)->state = ST;
            printf("Job [%d] (%d) stopped by signal %d\n", pid2jid(pid), pid, SIGTSTP);
        }
        else if(WTERMSIG(status) > 0) printf("Job [%d] (%d) terminated by signal %d\n", pid2jid(pid), pid, SIGINT);
        if(getjobpid(jobs, pid)->state != ST) deletejob(jobs, pid);
        pid = waitpid(-1, &status, WNOHANG | WUNTRACED);
    }
    return;
}

/*
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.
 */
void sigint_handler(int sig)
{
    pid_t pid = fgpid(jobs);
    if(pid == 0) return;
    if(kill(-pid, SIGINT) < 0) unix_error("kill error");
    return;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.
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

/* clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job) {
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->shline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
	clearjob(&jobs[i]);
}

/* maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs)
{
    int i, max=0;

    for (i = 0; i < MAXJOBS; i++)
	  if (jobs[i].jid > max) max = jobs[i].jid;
    return max;
}

/* addjob - Add a job to the job list */
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

/* deletejob - Delete a job whose PID=pid from the job list */
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

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs) {
    int i;
    for (i = 0; i < MAXJOBS; i++) if (jobs[i].state == FG) return jobs[i].pid;
    return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid) {
    int i;
    if (pid < 1) return NULL;
    for (i = 0; i < MAXJOBS; i++) if (jobs[i].pid == pid) return &jobs[i];
    return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid)
{
    int i;
    if (jid < 1) return NULL;
    for (i = 0; i < MAXJOBS; i++) if (jobs[i].jid == jid) return &jobs[i];
    return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid)
{
    int i;

    if (pid < 1) return 0;
    for (i = 0; i < MAXJOBS; i++) if (jobs[i].pid == pid) return jobs[i].jid;
    return 0;
}

/* listjobs - Print the job list */
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
            case FG:
                printf("Foreground");
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
 * unix_error - unix-style error routine
 */
void unix_error(char *msg)
{
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

/*
 * app_error - application-style error routine
 */
void app_error(char *msg)
{
    fprintf(stdout, "%s\n", msg);
    exit(1);
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler)
{
    struct sigaction action, old_action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    action.sa_flags = SA_RESTART; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0)
	unix_error("Signal error");
    return (old_action.sa_handler);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 */
void sigquit_handler(int sig)
{
    printf("Terminating after receipt of SIGQUIT signal\n");
    exit(1);
}


/*
 * alloc_cmd - Dynamically allocate the command structure
 */
cmd_t *alloc_cmd(void) {
    cmd_t *cmd = malloc(sizeof(cmd_t));
    return cmd;
}

/*
 * free_cmd - Free the command structure
 */
void free_cmd(cmd_t *c) {
    free(c);
}

/*
 * print_cmd - Print the command structure for debugging. You should
 * not enable this debugging print when submitting the code
 */
void print_cmd(cmd_t *c) {
    // int argc;
    // char *argv[MAXARGS];
    // int is_head;
    // int bg;
    // int pid;
    // int pipe[2];
    // struct cmd_t *next;
    // char shline[MAXLINE];
    printf("------------ printing cmd ------------\n");
    printf("number of args: %d\n", c->argc);
    for(int i = 0; i < c->argc; i++) printf("arg %d : %s\n", i, c->argv[i]);
    printf("is head: %d\n", c->is_head);
    printf("is bg: %d\n", c->bg);
    printf("pid: %d\n", c->pid);
    printf("pipe: %d %d\n", c->pipe[PIPE_OUT], c->pipe[PIPE_IN]);
    printf("shell: %s\n", c->shline);
    printf("--------------------------------------\n");
}

