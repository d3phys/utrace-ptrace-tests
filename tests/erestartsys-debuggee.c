/* Child -m32 built program only to be called by `./erestartsys-debugger'.

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
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stddef.h>
#include <pty.h>
#include <string.h>

#ifndef __i386__

int
main (void)
{
  /* stderr from child would not be visible due to forkpty().  */
  return 77;
}

#else	/* __i386__ */

static void
handler_fail (int signo)
{
  signal (SIGABRT, SIG_DFL);
  abort ();
}

static volatile unsigned long long func_data;

static void
func (void)
{
  func_data = 42;
  raise (SIGUSR2);
  assert (0);
}

static volatile unsigned long long child_retval;
static volatile unsigned long long child_errno;

int
main (int argc, char **argv)
{
  long l;
  unsigned u;
  /* Its size must match `erestartsys-debugger.c'.  */
  char buf[0x100];
  ssize_t ssize;
  int i;
  void *voidp;

  setbuf (stdout, NULL);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);

  if (argc != 2 || strcmp (argv[1], "foo") != 0)
    {
      fprintf (stderr, "%s: You must run ./erestartsys-debugger instead!\n",
	       argv[0]);
      return 77;
    }

  voidp = memset (buf, 0, sizeof buf);
  assert (voidp == buf);
  assert ((unsigned long) &func_data % sizeof (func_data) == 0);
  assert ((unsigned long) &child_retval % sizeof (func_data) == 0);
  assert ((unsigned long) &child_errno % sizeof (func_data) == 0);
  i = snprintf (buf, sizeof buf, "data_size 0x%x\nfunc %p\nfunc_data %p\n"
				 "child_retval %p\nchild_errno %p\n",
		(unsigned int) sizeof (func_data), func, &func_data,
		&child_retval, &child_errno);
  assert (i >= 1 && i < sizeof buf);
  ssize = write (STDOUT_FILENO, buf, sizeof buf);
  assert (ssize == sizeof buf);

  l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
  assert (l == 0);
  errno = 0;
  u = sleep (2);
  child_retval = u;
  child_errno = errno;
  i = raise (SIGUSR1);
  assert (i == 0);
  assert (0);

  assert (0);
}

#endif	/* __i386__ */
