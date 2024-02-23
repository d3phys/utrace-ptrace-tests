/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.
   
   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* Here we fail on PTRACE_CONT, SIG_!=0 with inferior's SA_RESETHAND
     on kernel-2.6.23-0.170.rc5.git1.fc8.x86_64 .
   The test passes on kernel.org linux-2.6.22-rc4-git7.x86_64 .  */

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

#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

static void handler_usr1 (int signo)
{
  assert (signo == SIGUSR1);
  exit (42);
}

static void
child_f (void)
{
  pause ();
  /* NOTREACHED */
  assert (0);
}

static pid_t child;

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  child = 0;
}

static void
handler_fail (int signo)
{
  cleanup ();
  signal (signo, SIG_DFL);
  raise (signo);
}

int main (void)
{
  struct sigaction act;
  int i;
  int status;

  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);

  memset (&act, 0, sizeof act);
  act.sa_flags = SA_RESETHAND;
  act.sa_handler = handler_usr1;
  i = sigaction (SIGUSR1, &act, NULL);
  assert (i == 0);

  child = fork();
  assert(child >= 0);
  if (child == 0) /* child */
    child_f ();	/* does not return */

  /* Parent.  */

  /* Just some safety to finish fork(2), maybe not required.  */
  usleep (50 * 1000);

  i = ptrace (PTRACE_ATTACH, child, NULL, NULL);
  assert (i == 0);
  i = waitpid (child, &status, 0);
  assert (i == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  i = ptrace (PTRACE_CONT, child, NULL, (void *) (unsigned long) SIGUSR1);
  assert (i == 0);
  i = waitpid (child, &status, 0);
  assert (i == child);
  if (WIFEXITED (status) && WEXITSTATUS (status) == 42)
    {
#if 0
      puts ("PASS");
#endif
      exit (0);
    }
  if (WIFSIGNALED (status) && WTERMSIG (status) == SIGUSR1)
    {
#if 0
      puts ("FAIL");
#endif
      exit (1);
    }
  assert (0);
  /* NOTREACHED */
}
