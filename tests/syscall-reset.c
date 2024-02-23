/* Test case for modifying syscall return value register at entry tracing.

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

#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

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

int
main (int argc, char **argv)
{
  pid_t got_pid;
  int status;
  long l;

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);

  child = fork ();
  switch (child)
    {
      case -1:
        assert_perror (errno);
	break;

      case 0:
	l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
	assert (l == 0);

	status = raise (SIGUSR1);
	assert (status == 0);

	errno = 0;
	l = syscall (-23, 1, 2, 3);
	assert (l == -1l);
	assert (errno != 0);

	if (errno == ENOTTY)
	  return 0;

	/* Some kernels return -syscallnumber in such case.  */
	if (errno == 23)
	  return 1;

	printf ("errno %d (%m)\n", errno);

	assert (errno == ENOSYS);
	return 1;

      default:
        break;
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  /*
   * On i386, it has always been that at entry tracing, eax = -ENOSYS and
   * orig_eax = incoming %eax value (syscall #).  Here, ptrace can change
   * the value of orig_eax to affect what syscall the thread will attempt.
   * If the orig_eax value is invalid (< 0 or > __NR_syscall_max), then no
   * syscall is attempted and %eax is returned as it is.  This means that
   * for an invalid syscall # in orig_eax--whether originally there or put
   * there by ptrace while at the entry stop--whatever register state (eax
   * included) that ptrace left there after the entry tracing stop will be
   * what the user sees.  Thus you can use syscall entry tracing to do what
   * PTRACE_SYSEMU does, which is to let the debugger intercept and
   * simulate system call attempts precisely how it chooses.  This is
   * simpler than tweaking at both entry and exit tracing just to jump
   * around the syscall and set the eax value you want.  This matters even
   * more in utrace, because you can request entry tracing only and not
   * exit tracing (so it stays quite simple).
   */

  errno = 0;
  l = ptrace (PTRACE_SYSCALL, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

#define OLDVAL		((long) -ENOSYS)
#define NEWVAL		((long) -ENOTTY)
#ifdef __i386__
# define RETREG		offsetof (struct user_regs_struct, eax)
#elif defined __x86_64__
# define RETREG		offsetof (struct user_regs_struct, rax)
#elif defined __powerpc__

  /* PPC http://marc.info/?t=125952920400004 cannot set return value on the
     entry, skip over to the syscall exit ptrace side.  */

# define SYSCALLREG	offsetof (struct pt_regs, gpr[0])
# define RETREG		offsetof (struct pt_regs, gpr[3])

  errno = 0;
  l = ptrace (PTRACE_PEEKUSER, child, SYSCALLREG, 0l);
  assert_perror (errno);
  assert (l == -23L);

  errno = 0;
  l = ptrace (PTRACE_SYSCALL, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  /* PPC has positive error numbers, they are indicated by the SO bit in CR.  */

# undef OLDVAL
# define OLDVAL		((long) ENOSYS)
# undef NEWVAL
# define NEWVAL		((long) ENOTTY)

#endif

#ifdef RETREG

  errno = 0;
  l = ptrace (PTRACE_PEEKUSER, child, RETREG, 0l);
  assert_perror (errno);
  assert (l == OLDVAL);

  l = ptrace (PTRACE_POKEUSER, child, RETREG, NEWVAL);
  assert_perror (errno);
  assert (l == 0);

#else

  fprintf (stderr, "%s: Port this test to this machine!\n", argv[0]);
  return 77;

#endif

  errno = 0;
  l = ptrace (PTRACE_CONT, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);

  if (WIFEXITED (status))
    return WEXITSTATUS (status);

  printf ("unexpected child status %x\n", status);

  return 3;
}
