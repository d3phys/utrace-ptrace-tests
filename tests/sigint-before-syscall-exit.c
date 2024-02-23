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
#include <asm/unistd.h>

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stddef.h>

/* On RHEL-4 it is present only in <linux/ptrace.h> in
   /lib/modules/`uname -r`/{build,source}.  */
#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS	0x4200
#endif
#ifndef PTRACE_O_TRACEEXEC
#define PTRACE_O_TRACEEXEC	0x00000010
#endif
#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC	4
#endif

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
  signal (SIGABRT, SIG_DFL);
  abort ();
}

#define WEVENT(s) (((s) & 0xFF0000) >> 16)

int main (int argc, char **argv)
{
  long l;
  int status, i;
  pid_t pid;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);

      // Prevent rt_sigprocmask() call called by glibc after raise().
      i = syscall (__NR_tkill, getpid (), SIGSTOP);
      assert (i == 0);

      execl ("/bin/false", "false", NULL);
      /* NOTREACHED */
      assert (0);
    default:
      break;
    }

  errno = 0;
  pid = waitpid (child, &status, 0);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  errno = 0;
  l = ptrace (PTRACE_SETOPTIONS, child, NULL, (void *) PTRACE_O_TRACEEXEC);
  assert_perror (errno);
  assert (l == 0);

  /* Enter execl().  */

  errno = 0;
  l = ptrace (PTRACE_SYSCALL, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  pid = waitpid (child, &status, 0);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);
  assert (WEVENT (status) == 0);

  /* Leave execl().  */

  errno = 0;
  l = ptrace (PTRACE_SYSCALL, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  pid = waitpid (child, &status, 0);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);
  assert (WEVENT (status) == PTRACE_EVENT_EXEC);

  /* Check SIGINT vs. SYSCALL_EXIT.  */

  errno = 0;
  i = kill (child, SIGINT);
  assert_perror (errno);
  assert (i == 0);

  errno = 0;
  l = ptrace (PTRACE_CONT, pid, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  pid = waitpid (child, &status, 0);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  /* We must see SIGINT, not SYSCALL_EXIT.  */
  assert (WSTOPSIG (status) == SIGINT);

  return 0;
}
