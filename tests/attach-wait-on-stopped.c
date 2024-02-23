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

#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>


static void
child_f (void)
{
  raise (SIGSTOP);
  abort ();
  /* NOTREACHED */
}

static pid_t child;

static const char *handler_state;

static void
handler (int signo)
{
  if (child > 0)
    kill (child, SIGKILL);
  //  abort ();
  fprintf (stderr, "timeout: %s\n", handler_state);
  exit (1);
}

static void attach (const char *state)
{
  int i;
  int status;

  handler_state = state;
  signal (SIGALRM, handler);
  alarm (1);

  i = ptrace (PTRACE_ATTACH, child, NULL, NULL);
  //assert (i == 0);
  if (i != 0) error (1, errno, "%s", state);
  i = waitpid (child, &status, 0);
  //  assert (i == child);
  if (i != child) {
    if (-1 == i)  error (1, errno, "waitpid");
    else {
      fprintf (stderr, "waitpid pid mismatch\n");
      exit (1);
    }
  }
  //  assert (WIFSTOPPED (status) != 0);
  if (WIFSTOPPED (status) == 0) {
    fprintf (stderr, "WIFSTOPPED false\n");
    exit (1);
  }
  //  assert (WSTOPSIG (status) == SIGSTOP);
  if (WSTOPSIG (status) != SIGSTOP) {
    fprintf (stderr, "WSTOPSIG !- SIGSTOP\n");
    exit (1);
  }

  alarm (0);
}

int main (void)
{
  int i;

  child = fork();
  switch (child)
    {
      case -1:
        perror ("fork()");
	exit (1);
	/* NOTREACHED */
      case 0:
        child_f ();
	/* NOTREACHED */
      default:;
	/* PASSTHRU */
    }
  /* Parent.  */

  sleep (1);

  /* Buggy:
  kernel-xen-2.6.19-1.2898.2.3.fc7.i686
  kernel-2.6.20-1.2925.fc6.i586
  kernel-2.6.20-1.2928.rm1.fc6.x86_64
     Fixed:
  kernel-2.6.20-1.2935.rm1.fc6.x86_64
  kernel-2.6.20-1.2935.rm2.fc6.x86_64
  */
  attach ("first PTRACE_ATTACH");

  /* Buggy:
  kernel-2.6.20-1.2935.rm1.fc6.x86_64
     Fixed:
  kernel-2.6.20-1.2935.rm2.fc6.x86_64
  */
  errno = 0;
  ptrace (PTRACE_PEEKUSER, child, NULL, NULL);
  //assert_perror (errno);
  if (errno != 0) error (1, errno, "PTRACE_PEEKUSER");

  // Old powerpc did not have PTRACE_GETREGS.
#ifdef PTRACE_GETREGS
  unsigned char regs[0x10000];
# ifdef __sparc__
  i = ptrace (PTRACE_GETREGS, child, regs, NULL);
# else
  i = ptrace (PTRACE_GETREGS, child, NULL, regs);
#endif
# ifdef __powerpc__
  // New headers, old kernel, no PTRACE_GETREGS call.
  if (i != 0 && errno == EIO)
    i = 0;
# endif
  //assert (i == 0);
  if (i != 0) error (1, errno, "PTRACE_GETREGS");
#endif

  i = ptrace (PTRACE_DETACH, child, NULL, NULL);
  //assert (i == 0);
  if (i != 0) error (1, errno, "PTRACE_DETACH");

  /* Disabled for kernel-2.6.30 rcs as the requested behavior is now in
     stopped-attach-transparency and this functionality was more accidental in
     older kernels.  */
#if 0
  /* Buggy:
  kernel-2.6.20-1.2935.rm2.fc6.x86_64
  */
  attach ("second PTRACE_ATTACH");
#endif

  //  puts ("OK");
  kill (child, SIGKILL);
  //return 0;
  exit (0);
}
