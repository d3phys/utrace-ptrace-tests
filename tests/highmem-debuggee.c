/* Child -m32 built program only to be called by `./highmem-debugger'.

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
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#if !(defined __i386__ || (defined __powerpc__ && !defined __powerpc64__) \
      || (defined __s390__ && !defined __s390x__))

int
main (int argc, char **argv)
{
#if defined __s390x__ || defined __x86_64__ || defined __powerpc64__
  fprintf (stderr, "%s: 32-bit biarch system libraries required!\n", argv[0]);
#endif

  return 77;
}

#else	/* supported 32-bit arch */

static void
handler_fail (int signo)
{
  signal (SIGABRT, SIG_DFL);
  abort ();
}

static volatile unsigned long long data = 42;

int
main (int argc, char **argv)
{
  long l;
  /* Its size must match `highmem-debugger.c'.  */
  char buf[0x100];
  ssize_t ssize;
  int i;
  void *voidp;

  setbuf (stdout, NULL);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  if (argc != 2 || strcmp (argv[1], "foo") != 0)
    {
      fprintf (stderr, "%s: You must run ./highmem-debugger instead!\n",
	       argv[0]);
      return 77;
    }

  /* The parent ensures sizeof (void *) == 8.  */
  assert (sizeof (void *) == 4);

  voidp = memset (buf, 0, sizeof buf);
  assert (voidp == buf);
  assert ((unsigned long) &data % sizeof (data) == 0);
  i = snprintf (buf, sizeof buf, "data_size 0x%x\ndata %p\n",
		(unsigned int) sizeof (data), &data);
  assert (i >= 1 && i < sizeof buf);
  ssize = write (STDOUT_FILENO, buf, sizeof buf);
  assert (ssize == sizeof buf);

  errno = 0;
  l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);
  raise (SIGUSR1);
  assert (0);
}

#endif	/* supported 32-bit arch */
