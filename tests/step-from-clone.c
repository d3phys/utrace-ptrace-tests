/* Test case for PTRACE_SINGLESTEP at PTRACE_EVENT_{CLONE,FORK,VFORK} stop
   after non-PTRACE_SYSCALL/SINGLESTEP entry to the clone/fork call.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

#define _GNU_SOURCE 1
#ifdef __ia64__
#define ia64_fpreg ia64_fpreg_DISABLE
#define pt_all_user_regs pt_all_user_regs_DISABLE
#endif /* __ia64__ */
#include <sys/ptrace.h>
#ifdef __ia64__
#undef ia64_fpreg
#undef pt_all_user_regs
#endif /* __ia64__ */
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#if defined __i386__ || defined __x86_64__
#include <sys/debugreg.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <stddef.h>

#include <asm/unistd.h>

#if defined __x86_64__
# define REGISTER_CALLNO	offsetof (struct user_regs_struct, orig_rax)
# define REGISTER_RETVAL	offsetof (struct user_regs_struct, rax)
#elif defined __i386__
# define REGISTER_CALLNO	offsetof (struct user_regs_struct, orig_eax)
# define REGISTER_RETVAL	offsetof (struct user_regs_struct, eax)
/* __powerpc64__ defines both the symbols.  */
#elif defined __powerpc__
# define REGISTER_CALLNO	offsetof (struct pt_regs, gpr[0])
# define REGISTER_RETVAL	offsetof (struct pt_regs, gpr[3])
#elif defined __powerpc64__
# error "__powerpc__ should be defined"
/* __s390x__ defines both the symbols.  */
#elif defined __s390__
/* FIXME */
#elif defined __s390x__
# error "__s390__ should be defined"
#endif

/* On RHEL-4 it is present only in <linux/ptrace.h> in
   /lib/modules/`uname -r`/{build,source}.  */
#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS	0x4200
#endif
#ifndef PTRACE_O_TRACEFORK
#define PTRACE_O_TRACEFORK	0x00000002
#endif
#ifndef PTRACE_O_TRACEVFORK
#define PTRACE_O_TRACEVFORK	0x00000004
#endif
#ifndef PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE	0x00000008
#endif
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD	0x00000001
#endif
#ifndef PTRACE_EVENT_FORK
#define PTRACE_EVENT_FORK	1
#endif

static void
test_fork (void)
{
  /* Don't let the SIGCHLD for the grandchild's death louse
     up the sequence of ptrace stops by the parent.  */
  sigset_t set;
  sigemptyset (&set);
  sigaddset (&set, SIGCHLD);
  if (sigprocmask (SIG_BLOCK, &set, NULL))
    {
      perror ("sigprocmask");
      _exit (3);
    }

  if (ptrace (PTRACE_TRACEME, 0, 0, 0) == -1)
    {
      perror ("ptrace(PTRACE_TRACEME)");
      _exit (2);
    }

  /* First, let parent know I'm here by sending myself a signal.  */
  raise (SIGUSR1);

  switch (fork ())
    {
    case -1:
      perror ("fork");
      _exit (1);

    case 0:			/* child */
      _exit (0);

    default:			/* parent */
      _exit (0);
    }
}

pid_t child;
pid_t grandchild;

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  if (grandchild > 0)
    kill (grandchild, SIGKILL);
}

static void
handler_fail (int signo)
{
  cleanup ();
  signal (SIGABRT, SIG_DFL);
  assert (0);
}

int
main (int ac, char *av[])
{
  int status;
  pid_t pid;
#ifdef REGISTER_CALLNO
  long callno;
#endif
#ifdef REGISTER_RETVAL
  long retval;
#endif
  int result;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (2);

  child = fork ();
  if (child == (pid_t) - 1)
    {
      perror ("fork");
      exit (1);
    }
  if (child == 0)
    test_fork ();		/* does not return */

  errno = 0;

  /* I am the parent, I'll be debugging the child which will
   * call fork(). The first thing I expect to see from the
   * child is a SIGUSR1 it sends to itself.
   */
  pid = waitpid (-1, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  ptrace (PTRACE_SETOPTIONS, child, 0,
	  PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK);
  assert_perror (errno);

  /* Let child continue and fork */
  ptrace (PTRACE_CONT, child, 0, 0);
  assert_perror (errno);

  /* PTRACE_O_TRACEFORK: child should get SIGTRAP, and grandchild SIGSTOP */
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8)));

  grandchild = waitpid (-1, &status, 0);
  assert (grandchild != child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  /* Just continue fork child, it should exit quickly.  */
  ptrace (PTRACE_CONT, grandchild, 0, 0);
  assert_perror (errno);
  pid = waitpid (-1, &status, 0);
  assert (pid == grandchild);
  assert (WIFEXITED (status));
  assert (WEXITSTATUS (status) == 0);

  /* Single-step the fork parent stopped at the PTRACE_EVENT_FORK stop.  */
  ptrace (PTRACE_SINGLESTEP, child, 0, 0);
  assert_perror (errno);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert ((status >> 8) == SIGTRAP);

  result = 77;
#ifdef REGISTER_CALLNO
  callno = ptrace (PTRACE_PEEKUSER, child, (void *) REGISTER_CALLNO, NULL);
  assert_perror (errno);

  /* The test fails if this is a normal single-step stop after the
     instruction following the syscall inside glibc's "fork".
     It should be the syscall-exit stop for "fork ()", where the
     return value is the fork child's PID.  */
  switch (callno)
    {
    case -1:
      result = 1;
      break;

# ifdef __NR_fork
    case __NR_fork:
# endif
# ifdef __NR_clone
    case __NR_clone:
# endif
# ifdef __NR_clone2
    case __NR_clone2:
# endif
      result = 0;
#ifdef REGISTER_RETVAL
      retval = ptrace (PTRACE_PEEKUSER, child, (void *) REGISTER_RETVAL, NULL);
      assert_perror (errno);

      assert (retval == grandchild);
#endif
      break;

    default:
      fprintf (stderr, "unexpected syscall %#lx\n", callno);
      result = 2;
      assert (!"unexpected syscall");
    }
#endif

  ptrace (PTRACE_CONT, child, 0, 0);
  assert_perror (errno);

  /* See that both exited */
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFEXITED (status));
  assert (WEXITSTATUS (status) == 0);

  return result;
}
