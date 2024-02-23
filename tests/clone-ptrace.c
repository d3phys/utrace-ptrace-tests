/* Test case whether CLONE_PTRACE works right.

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
#include <asm/unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <sched.h>
#include <error.h>

#ifdef __ia64__
extern int __clone2 (int (*fn)(void *), void *child_stack_base,
		     size_t stack_size, int flags, void *arg, ...);
#define clone2 __clone2
#else
#define clone2(func, stack_base, size, flags, arg...) \
	clone (func, (stack_base) + (size), flags, arg)
#endif

static unsigned char child_stack[4 * 1024] __attribute__ ((aligned (16)));

static int
exit0 (void *unused)
{
  _exit (0);
}

pid_t child, grandchild;

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  child = 0;
  if (grandchild > 0)
    kill (grandchild, SIGKILL);
  grandchild = 0;
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
  int l, status;
  pid_t pid;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  child = fork ();
  if (child == -1)
    {
      perror ("fork");
      exit (1);
    }

  if (child == 0)
    {
      // child
      l = ptrace (PTRACE_TRACEME, 0, (void *) 0, (void *) 0);
      assert (l == 0);
      // Prevent rt_sigprocmask() call called by glibc after raise().
      syscall (__NR_tkill, getpid (), SIGSTOP);
      assert (l == 0);

      clone2 (exit0, child_stack, sizeof (child_stack),
		      CLONE_PTRACE | SIGCHLD, NULL);
      /* We never get here due to our parent tracer.  */
      assert (0);
    }

  // parent
  pid = waitpid (-1, &status, 0);
  assert (pid == child);
//fprintf (stderr, "s:%d e:%d\n", WIFSTOPPED (status), WIFEXITED (status));
  assert (WIFSTOPPED (status));
//fprintf (stderr, "sig:%d\n", WSTOPSIG (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  /* Enter into clone().  */

  errno = 0;
  ptrace (PTRACE_SYSCALL, pid, (void *) 1, (void *) 0);
  assert_perror (errno);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  /* Leave from clone().  */

  errno = 0;
  ptrace (PTRACE_SYSCALL, pid, (void *) 1, (void *) 0);
  assert_perror (errno);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  /* Catch the new child being traced due to CLONE_PTRACE.  */

  grandchild = waitpid (-1, &status, 0);
  assert (grandchild > 0);
  assert (grandchild != child);
  if (WIFEXITED (status))
    {
      /* Expected failure - the child finished.  It did not even get its
	 SIGSTOP despite CLONE_PTRACE was used to create it.
	 Detected on: kernel-2.6.27-0.173.rc0.git11.fc10.x86_64  */
      assert (WEXITSTATUS (status) == 0);
      return 1;
    }
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  /* Test we can trace the new child.  */

  errno = 0;
  ptrace (PTRACE_SYSCALL, grandchild, (void *) 1, (void *) 0);
  if (errno == ESRCH)
    {
      /* Expected failure - we are not the ptrace parent of the new child
	 despite CLONE_PTRACE was used to create it.  Still it got at least its
	 SIGSTOP due to CLONE_PTRACE.
	 Detected on: kernel-2.6.27-0.329.rc6.git2.fc10.x86_64  */
      return 1;
    }
  assert_perror (errno);

  pid = waitpid (grandchild, &status, 0);
  assert (pid == grandchild);
  assert (WIFSTOPPED (status));
  if (WSTOPSIG (status) != SIGTRAP)
    error (1, 0, "(WSTOPSIG = %d) != SIGTRAP", WSTOPSIG (status));

  return 0;
}
