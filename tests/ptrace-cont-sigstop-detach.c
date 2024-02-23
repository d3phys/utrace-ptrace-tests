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

#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>

#define DELAY() sleep (1)

static void loop (void)
{
  for (;;)
    pause ();
  /* NOTREACHED */
  abort ();
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
handler (int signo)
{
  cleanup ();
  signal (signo, SIG_DFL);
  raise (signo);
}

#if 0
static void
print_status(int tid)
{
  int fd, n;
  char buf[8192];
  char fn[64];

  snprintf(fn, sizeof fn, "/proc/%d/status", tid);
  fd = open(fn, O_RDONLY);
  n = read(fd, buf, sizeof buf - 1);
  close(fd);
  if (n > 0)
    {
      char *s;

      buf[n] = 0;
      s = strstr (buf, "\nUid:\t");
      if (s != NULL);
        n = (s + 1) - buf;
      write(1, buf, n);
    }
}
#endif

int main (void)
{
  void (*handler_orig) (int signo);
  pid_t got_pid;
  int status;

  setbuf (stdout, NULL);

  child = fork ();
  switch (child)
    {
      case -1:
	abort ();
      case 0:
	loop ();
	/* NOTREACHED */
	abort ();
      default:
        break;
    }

  atexit (cleanup);
  handler_orig = signal (SIGINT, handler);
  assert (handler_orig == SIG_DFL);
  handler_orig = signal (SIGABRT, handler);
  assert (handler_orig == SIG_DFL);
  handler_orig = signal (SIGALRM, handler);
  assert (handler_orig == SIG_DFL);
  alarm (20);

  errno = 0;
  ptrace (PTRACE_ATTACH, child, NULL, NULL);
  assert_perror (errno);

  DELAY ();

  /* Deliver one SIGSTOP just for sure.
     If the process was already stopped AND some other process (like shell)
     has already waited for it we would get stuck in waitpid ().  */

  errno = 0;
  ptrace (PT_CONTINUE, child, (void *) 1UL, (void *) (unsigned long) SIGSTOP);
  /* For unstopped processes the preventive signal may ESRCH.  */

  DELAY ();

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);

  /* Check if the thread has exited.  */
  assert (!WIFEXITED (status));
  assert (!WIFSIGNALED (status));

  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  DELAY ();

  errno = 0;
  ptrace (PTRACE_DETACH, child, (void *) 1UL, (void *) 0UL);
  if (errno == ESRCH)
    {
#if 0
      fputs ("utrace bug hit\n", stderr);
      print_status(child);
      abort ();
#else
      return 1;
#endif
    }
  assert_perror (errno);

  alarm (0);
  return 0;
}
