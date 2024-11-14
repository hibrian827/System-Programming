#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/personality.h>

#include "snudbg.h"
#include "procmaps.h"

int num_bps = 0;
breakpoint_t bps[MAX_BPS];

/* HINT: No need to change this function */
void die(char* message) {
    WARN("Failed with message: '%s'\n", message);
    exit(-1);
}

/* HINT: No need to change this function */
void handle_regs(struct user_regs_struct *regs) {
    fprintf(stdout, "\t");
    PRINT_REG(rax);
    PRINT_REG(rbx);
    PRINT_REG(rcx);
    PRINT_REG(rdx);
    fprintf(stdout, "\n");

    fprintf(stdout, "\t");
    PRINT_REG(rbp);
    PRINT_REG(rsp);
    PRINT_REG(rsi);
    PRINT_REG(rdi);
    fprintf(stdout, "\n");

    fprintf(stdout, "\t");
    PRINT_REG(r8);
    PRINT_REG(r9);
    PRINT_REG(r10);
    PRINT_REG(r11);
    fprintf(stdout, "\n");

    fprintf(stdout, "\t");
    PRINT_REG(r12);
    PRINT_REG(r13);
    PRINT_REG(r14);
    PRINT_REG(r15);
    fprintf(stdout, "\n");

    fprintf(stdout, "\t");
    PRINT_REG(rip);
    PRINT_REG(eflags);
    fprintf(stdout, "\n");
}

/* HINT: No need to change this function */
void no_aslr(void) {
    unsigned long pv = PER_LINUX | ADDR_NO_RANDOMIZE;

    if (personality(pv) < 0) {
        if (personality(pv) < 0) {
            die("Failed to disable ASLR");
        }
    }
    return;
}

/* HINT: No need to change this function */
void tracee(char* cmd[]) {
    LOG("Tracee with pid=%d\n", getpid());

    no_aslr();
    
    if(ptrace(PTRACE_TRACEME, NULL, NULL, NULL)<0){
        die("Error traceing myself");
    }

    LOG("Loading the executable [%s]\n", cmd[0]);
    execvp(cmd[0], cmd);
}

/* INSTRUCTION: YOU SHOULD NOT CHANGE THIS FUNCTION */    
void dump_addr_in_hex(const ADDR_T addr, const void* data, size_t size) {
    uint i;
    for (i=0; i<size/16; i++) {
        printf("\t %llx ", addr+(i*16));
        for (uint j=0; j<16; j++) {
            printf("%02x ", ((unsigned char*)data)[i*16+j]);
        }
        printf("\n");
    }

    if (size%16 != 0) {
        // the rest
        printf("\t %llx ", addr+(i*16));
        for (uint j=0; j<size%16; j++) {
            printf("%02x ", ((unsigned char*)data)[i*16+j]);
        }
        printf("\n");
    }
}

/* HINT: No need to change this function */
void handle_help(void) {
    LOG("Available commands: \n");
    LOG("\t regs | get [REG] | set [REG] [value]\n");
    LOG("\t read [addr] [size] | write [addr] [value] [size]\n");
    LOG("\t step | continue | break [addr]\n");
    LOG("\t help\n");
    return;
}

void set_debug_state(int pid, enum debugging_state state) {
    if(state == SINGLE_STEP) {
        if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)<0) {
            die("Error tracing syscalls");
        }
    } else if (state == NON_STOP) {
        ptrace(PTRACE_CONT, pid, NULL, NULL);
    }
    return;
}


/* 
   Read the memory from @pid at the address @addr with the length @len.
   The data read from @pid will be written to @buf.
*/
void handle_read(int pid, ADDR_T addr, unsigned char *buf, size_t len) {
    size_t i = 0;
    for(i = 0; i < len / 8; i++) {
        long data = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i * 8), NULL);
        for(size_t j = 0; j < 8; j++) {
            char temp = (data >> (j * 8)) & 0xff;
            memcpy(buf + i * 8 + j, &temp, sizeof(char));
        }
    }
    if(len % 8 != 0) {
        long data = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i * 8), NULL);
        for(size_t j = 0; j < len % 8; j++) {
            char temp = (data >> (j * 8)) & 0xff;
            memcpy(buf + i * 8 + j, &temp, sizeof(char));
        }
    }
    dump_addr_in_hex(addr, buf, len);
    return;
}

/* 
   Write the memory to @pid at the address @addr with the length @len.
   The data to be written is placed in @buf.
*/
void handle_write(int pid, ADDR_T addr, unsigned char *buf, size_t len) {
    // ------------------------------------------------------------------------------
    // size_t i = 0;
    // for(i = 0; i < len / 8; i++) {
    //     char tmp_str[17];
    //     strncpy(tmp_str, (char *)(buf + i * 16), 16);
    //     tmp_str[16] = '\0';
    //     long tmp_hex = strtoull(tmp_str, NULL, 16);
    //     if (ptrace(PTRACE_POKEDATA, pid, addr + 8 * i, (void *)tmp_hex) == -1) {
    //         die("Error writing values to memory");
    //     }
    // }
    // if(len % 8 != 0) {
    //     char tmp_str[17];
    //     strncpy(tmp_str, (char *)(buf + i * 16), (len % 8) * 2);
    //     // for(int j = (len % 8) * 2; j < 16 ; j++) tmp_str[j] = '0';
    //     // tmp_str[16] = '\0';
    //     long tmp_hex = strtoull(tmp_str, NULL, 16);
    //     if (ptrace(PTRACE_POKEDATA, pid, addr + 8 * i, (void *)tmp_hex) == -1) {
    //         die("Error writing values to memory");
    //     }
    // }
    // ------------------------------------------------------------------------------
    char temp[17];
    char res[17];
    temp[16] = '\x0';
    res[16] = '\x0';
    size_t i;
    for(i = 0; i < len / 8; i++) {
        strncpy(temp, (char *)(buf + len * 2 - (i + 1) * 16), 16);
        for(int j = 0; j < 16; j += 2) {
          res[j] = temp[16 - j - 2];
          res[j + 1] = temp[16 - j - 1];
        }
        printf("%s\n", res);
    }
    if(len % 8 != 0) {
        long data = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i * 8), NULL);
        strncpy(temp, (char *)(buf), (len % 8) * 2);
        for(size_t j = (len % 8) * 2; j < 16 ; j += 2) sprintf(temp + j, "%02x\n", (char)((data >> ((j / 2) * 8)) & 0xff));
        temp[16] = '\x0';
        for(int j = 0; j < 16; j += 2) {
          res[j] = temp[16 - j - 2];
          res[j + 1] = temp[16 - j - 1];
        }
        printf("%s\n", res);
    }
    TODO_UNUSED(pid);
    TODO_UNUSED(addr);
    return;
}

/* 
   Install the software breakpoint at @addr to pid @pid.
*/
void handle_break(int pid, ADDR_T addr) {
    long inst = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr), NULL);
    breakpoint_t bp = {addr, (unsigned char)(inst & 0xff)};
    bps[num_bps] = bp;
    long bp_inst = (inst & ~0xff) | 0xcc;
    if (ptrace(PTRACE_POKEDATA, pid, addr, (void *)bp_inst) == -1) {
        die("Error making breakpoint");
    }
}

#define CMPGET_REG(REG_TO_CMP)                   \
    if (strcmp(reg_name, #REG_TO_CMP)==0) {      \
        printf("\t");                            \
        PRINT_REG(REG_TO_CMP);                   \
        printf("\n");                            \
    }

/* HINT: No need to change this function */
void handle_get(char *reg_name, struct user_regs_struct *regs) {
    CMPGET_REG(rax); CMPGET_REG(rbx); CMPGET_REG(rcx); CMPGET_REG(rdx);
    CMPGET_REG(rbp); CMPGET_REG(rsp); CMPGET_REG(rsi); CMPGET_REG(rdi);
    CMPGET_REG(r8);  CMPGET_REG(r9);  CMPGET_REG(r10); CMPGET_REG(r11);
    CMPGET_REG(r12); CMPGET_REG(r13); CMPGET_REG(r14); CMPGET_REG(r15);
    CMPGET_REG(rip); CMPGET_REG(eflags);
    return;
}


/*
  Set the register @reg_name with the value @value.
  @regs is assumed to be holding the current register values of @pid.
*/
void handle_set(char *reg_name, unsigned long value,
                struct user_regs_struct *regs, int pid) {
    if(strcmp(reg_name, "rax") == 0) regs->rax = value;
    else if(strcmp(reg_name, "rbx") == 0) regs->rbx = value;
    else if(strcmp(reg_name, "rcx") == 0) regs->rcx = value;
    else if(strcmp(reg_name, "rdx") == 0) regs->rdx = value;
    else if(strcmp(reg_name, "rdi") == 0) regs->rdi = value;
    else if(strcmp(reg_name, "rsi") == 0) regs->rsi = value;
    else if(strcmp(reg_name, "rbp") == 0) regs->rbp = value;
    else if(strcmp(reg_name, "rsp") == 0) regs->rsp = value;
    else if(strcmp(reg_name, "r8") == 0) regs->r8 = value;
    else if(strcmp(reg_name, "r9") == 0) regs->r9 = value;
    else if(strcmp(reg_name, "r10") == 0) regs->r10 = value;
    else if(strcmp(reg_name, "r11") == 0) regs->r11 = value;
    else if(strcmp(reg_name, "r12") == 0) regs->r12 = value;
    else if(strcmp(reg_name, "r13") == 0) regs->r13 = value;
    else if(strcmp(reg_name, "r14") == 0) regs->r14 = value;
    else if(strcmp(reg_name, "r15") == 0) regs->r15 = value;
    else if(strcmp(reg_name, "rip") == 0) regs->rip = value;
    else if(strcmp(reg_name, "eflags") == 0) regs->eflags = value;
    else {
      WARN("No such register as %s\n", reg_name);
      return;
    }
    set_registers(pid, regs);
    return;
}


void prompt_user(int child_pid, struct user_regs_struct *regs,
                 ADDR_T baseaddr) {
    
    const char* prompt_symbol = ">>> ";

    for(;;) {
        fprintf(stdout, "%s", prompt_symbol);
        char action[1024];
        scanf("%1024s", action);

        if(strcmp("regs", action)==0) {
            LOG("HANDLE CMD: regs\n");
            handle_regs(regs);
            continue;
        }

        if(strcmp("help", action)==0 || strcmp("h", action)==0) {
            handle_help();
            continue;
        }

        if(strcmp("get", action)==0) {
            char reg[10];
            scanf("%10s", reg);
            LOG("HANDLE CMD: get [%s]\n", reg);
            handle_get(reg, regs);
            continue;
        }

        if(strcmp("set", action)==0) {
            char reg[10];
            char hex[11];
            unsigned long long val;
            scanf("%10s", reg);
            scanf("%10s", hex);
            val = strtoull(hex, NULL, 16);
            LOG("HANDLE CMD: set [%s] to [%llu]\n", reg, val);
            handle_set(reg, val, regs, child_pid);
            continue;
        }

        if(strcmp("read", action)==0 || strcmp("r", action)==0) {
            char hex1[11];
            char hex2[11];
            ADDR_T addr;
            unsigned long long size;
            scanf("%10s", hex1);
            scanf("%10s", hex2);
            addr = strtoull(hex1, NULL, 16);
            size = strtoull(hex2, NULL, 16);
            unsigned char *res = malloc(size);
            LOG("HANDLE CMD: read [%llx][%llx] [%llx]\n", addr, baseaddr + addr, size);
            handle_read(child_pid, addr + baseaddr, res, size);
            free(res);
            continue;
        }

        if(strcmp("write", action)==0 || strcmp("w", action)==0) {
            // TODO
            char hex1[11];
            char hex2[MAX_RW + 2];
            char hex3[11];
            ADDR_T addr;
            unsigned char *val;
            unsigned long long size;
            scanf("%10s", hex1);
            scanf("%s", hex2);
            scanf("%10s", hex3);
            addr = strtoull(hex1, NULL, 16);
            if(strlen(hex2) > 2 && hex2[0] == '0' && hex2[1] == 'x') val = (unsigned char *)(hex2 + 2);
            else val = (unsigned char *)hex2;
            size = strtoull(hex3, NULL, 16);
            LOG("HANDLE CMD: write [%llx][%llx] [%s]<= 0x%llx\n", addr, baseaddr + addr, val, size);
            handle_write(child_pid, addr + baseaddr, val, size);
            continue;
        }

        if(strcmp("break", action)==0 || strcmp("b", action)==0) {
            ADDR_T addr;
            scanf("%llx", &addr);
            if(num_bps >= MAX_BPS) WARN("Too many breakpoints");
            else {
              LOG("HANDLE CMD: break [%llx][%llx]\n", addr, baseaddr + addr);
              handle_break(child_pid, addr + baseaddr);
              num_bps++;
            }
            continue;
        }

        if(strcmp("step", action)==0 || strcmp("s", action)==0) {
            LOG("HANDLE CMD: step\n");
            set_debug_state(child_pid, SINGLE_STEP);
            break;
        }

        if(strcmp("continue", action)==0 || strcmp("c", action)==0) {
            // TODO
            LOG("HANDLE CMD: continue\n");
            set_debug_state(child_pid, NON_STOP);
            break;
        }

        if(strcmp("quit", action)==0 || strcmp("q", action)==0) {
            LOG("HANDLE CMD: quit\n");
            exit(0);
        }

        WARN("Not available commands\n");
    }
}


/*
  Get the current registers of @pid, and store it to @regs.
*/
void get_registers(int pid, struct user_regs_struct *regs) {
    if(ptrace(PTRACE_GETREGS, pid, NULL, regs)<0) {
        die("Error getting registers");
    }
    return;
}


/*
  Set the registers of @pid with @regs.
*/
void set_registers(int pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
        die("Error setting registers");
    }
}


/*
  Get the base address of the main binary image, 
  loaded to the process @pid.
  This base address is the virtual address.
*/
ADDR_T get_image_baseaddr(int pid) {
    hr_procmaps** procmap = construct_procmaps(pid);
    ADDR_T baseaddr = (procmap[0])->addr_begin;
    return baseaddr;
}

/*
  Perform the job if the software breakpoint is fired.
  This includes to restore the original value at the breakpoint address.
*/
void handle_break_post(int pid, struct user_regs_struct *regs) {
    for(int i = 0; i < MAX_BPS; i++) {
        unsigned long long addr = bps[i].addr;
        unsigned char orig_val = bps[i].orig_value;
        if(addr == regs->rip - 1) {
            LOG("\tFOUND MATCH BP: [%d] [%llx][%02x]\n", i, addr, orig_val);
            long bp_inst = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr), NULL);
            long restore_inst = (bp_inst & ~0xff) | (long)orig_val;
            if(ptrace(PTRACE_POKEDATA, pid, addr, (void *)restore_inst) == -1) die("Error restoring orginal value");
            regs->rip = addr;
            if(ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) die("Error setting registers");
            // if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) die("Error tracing syscalls");
            // if(ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) die("Error getting registers");
            // if(ptrace(PTRACE_POKEDATA, pid, addr, (void *)bp_inst) == -1) die("Error restoring breakpoint");
            return;
        }
    }
}


/* HINT: No need to change this function */
void tracer(int child_pid) {
    int child_status;

    LOG("Tracer with pid=%d\n", getpid());

    wait(&child_status);

    ADDR_T baseaddr = get_image_baseaddr(child_pid);

    int steps_count = 0;
    struct user_regs_struct tracee_regs;
    set_debug_state(child_pid, SINGLE_STEP);

    while(1) {
        wait(&child_status);
        steps_count += 1;

        if(WIFEXITED(child_status)) {
            LOG("Exited in %d steps with status=%d\n",
                steps_count, child_status);
            break;
        }
        get_registers(child_pid, &tracee_regs);

        LOG("[step %d] rip=%llx child_status=%d\n", steps_count,
            tracee_regs.rip, child_status);

        handle_break_post(child_pid, &tracee_regs);
        prompt_user(child_pid, &tracee_regs, baseaddr);
    }
}

/* HINT: No need to change this function */
int main(int argc, char* argv[]) {
    char* usage = "USAGE: ./snudbg <cmd>";

    if (argc < 2){
        die(usage);
    }

    int pid = fork();

    switch (pid) {
    case -1:
        die("Error forking");
        break;
    case 0:
        tracee(argv+1);
        break;
    default:
        tracer(pid);
        break;
    }
    return 0;
}
