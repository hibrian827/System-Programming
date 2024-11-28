while ( 1 )
  {
    pid = waitpid(-1, &status, 3);
    pid_temp = pid;
    if ( pid <= 0 ) break;
    v2 = BYTE1(status);
    if ( (_BYTE)status == 127 )
    {
      v6 = jobs;
      v7 = jobs;
      while ( pid_temp != v7->pid )
      {
        if ( &jobs[16] == ++v7 )
        {
          printf("Lost track of (%d)\n", pid_temp);
          goto LABEL_38;
        }
      }
      v7->state = 3;
      v8 = 0;
      while ( pid_temp != v6->pid )
      {
        ++v8;
        ++v6;
        if ( v8 == 16 )
        {
          jid = 0LL;
          goto LABEL_23;
        }
      }
      jid = (unsigned int)jobs[v8].jid;
LABEL_23:
      fprintf(_bss_start, "Job [%d] (%d) stopped by signal %d\n", jid, pid_temp, v2);
    }
    else if ( __OFSUB__((status & 0x7F) + 1, 1) || (status & 0x7F) == 0 )
    {
      v3 = status & 0x7F;
      if ( (status & 0x7F) != 0 )
        goto LABEL_43;
      v4 = jobs;
      v5 = 0;
      while ( pid_temp != v4->pid )
      {
        ++v5;
        ++v4;
        if ( v5 == 16 )
          goto LABEL_10;
      }
      v3 = jobs[v5].jid;
LABEL_10:
      if ( deletejob(jobs, pid_temp) )
      {
       
      }
      else
      {
LABEL_13:
      }
    }
    else
    {
      v10 = jobs;
      v11 = 0;
      while ( pid_temp != v10->pid )
      {
        ++v11;
        ++v10;
        if ( v11 == 16 )
        {
          v12 = 0;
          goto LABEL_28;
        }
      }
      v12 = jobs[v11].jid;
LABEL_28:
      fprintf(_bss_start, "Job [%d] (%d) terminated by signal %d\n", v12, pid_temp, status & 0x7F);
    }
  }