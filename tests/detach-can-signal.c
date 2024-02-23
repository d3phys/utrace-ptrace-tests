/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

#define _GNU_SOURCE 1
#ifdef __ia64__
#define ia64_fpreg ia64_fpreg_DISABLE
#define pt_all_user_regs pt_all_user_regs_DISABLE
#endif	/* __ia64__ */
#include <sys/ptrace.h>
#ifdef __ia64__
#undef ia64_fpreg
#undef pt_all_user_regs
#endif	/* __ia64__ */
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#if defined __i386__ || defined __x86_64__
#include <sys/debugreg.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <alloca.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/unistd.h>

#define NR_CHILDREN 3

int
main (int ac, char * av[])
{
  int i;
  pid_t dpids[NR_CHILDREN];

  for (i = 0; i < NR_CHILDREN; i++) {
    pid_t pid = fork ();
    switch (pid) {
    case -1:
      perror ("fork");
      exit (1);
    case 0: // child
      {
	while (1) {
	  usleep (250000);
	}
      }
      break;
    default: // Parent
      dpids[i] = pid;
      break;
    }
  }

  for (i = 0; i < NR_CHILDREN; i++) {
    int status;

    if (ptrace (PTRACE_ATTACH, dpids[i], NULL, NULL) < 0) {
      perror ("ptrace -- for attach");
      exit (1);
    }
    if (waitpid (dpids[i], &status,  __WALL) < 0) {
      perror ("waitpid -- for attach");
      exit (1);
    }
  }

  for (i = 0; i < NR_CHILDREN; i++) {
    if (kill (dpids[i], SIGKILL))
      perror ("kill SIGKILL");
  }

  sleep (2);

  {
    int nr_resps;

    for (nr_resps = 0; 0 < waitpid (-1, NULL, WNOHANG); nr_resps++) {}
    exit ((0 == nr_resps) ? 1 : 0);
  }
}
