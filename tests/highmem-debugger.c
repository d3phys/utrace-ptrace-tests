/* Test the high 32-bits of address cause EIO iff they are non-zero with x86_64
   debugger and i386 debuggee.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

#define _GNU_SOURCE 1

#define DEBUGEE_PATHNAME "./highmem-debuggee"

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
#include <string.h>

#if !(defined __x86_64__ || defined __powerpc64__ || defined __s390x__)

int
main (void)
{
  return 77;
}

#else	/* supported 64-bit arch */

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

typedef unsigned long child_data_t;
typedef unsigned int child_address_t;
#define CHILD_UNSIGNED_INT_FORMAT "0x%x"
#define CHILD_ADDRESS_FORMAT "0x%x"

int
main (int argc, char **argv)
{
  long l;
  int status, i;
  pid_t pid;
  /* Its size must match `highmem-debuggee.c'.  */
  char buf[0x100];
  size_t buf_have = 0;
  unsigned int child_data_size;
  child_address_t data_p;
  child_data_t data;
  int fd[2];

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  errno = 0;
  i = pipe (fd);
  assert_perror (errno);
  assert (i == 0);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      errno = 0;
      i = close (fd[0]);
      assert_perror (errno);
      assert (i == 0);

      errno = 0;
      i = dup2 (fd[1], STDOUT_FILENO);
      assert_perror (errno);
      assert (i == STDOUT_FILENO);

      errno = 0;
      i = close (fd[1]);
      assert_perror (errno);
      assert (i == 0);

      execl (DEBUGEE_PATHNAME, "highmem-debuggee", "foo", NULL);
      assert (0);
    default:
      errno = 0;
      i = close (fd[1]);
      assert_perror (errno);
      assert (i == 0);

      break;
    }

  /* FIXME: We need to get in sync with the child as it must pass the
     PTRACE_TRACEME, we may get it caught inside of write(3) otherwise.  */
  i = sleep (1);
  assert (i == 0);

  while (buf_have != sizeof buf)
    {
      ssize_t got;
      int status;

      assert (buf_have < sizeof buf);
      got = read (fd[0], buf + buf_have, sizeof (buf) - buf_have);

      /* On x86_64 host without 32-bit build environment the child will just
	 return 77 as it was built with -m64 (and not -m32).  */
      if (got == 0 || (got == -1 && errno == EIO))
	{
	  /* Ignore the possible errors, just to avoid hang on WAITPID as we
	     cannot use WNOHANG there.  */
	  kill (child, SIGKILL);

	  if (waitpid (child, &status, 0) == child && WIFEXITED (status)
	       && WEXITSTATUS (status) == 77)
	    return 77;
	  assert (0);
	}
      assert (got > 0);
      buf_have += got;
    }
  assert (memchr (buf, 0, sizeof buf) != NULL);
  i = sscanf (buf, "data_size " CHILD_UNSIGNED_INT_FORMAT "\n"
		   "data " CHILD_ADDRESS_FORMAT "\n",
	      &child_data_size, &data_p);
  assert (i == 2);
  assert (sizeof (child_data_t) == child_data_size);
  assert (data_p % sizeof (child_data_t) == 0);

  /* The child ensures sizeof (void *) == 4.  */
  assert (sizeof (void *) == 8);
  assert (sizeof (child_address_t) == 4);
  assert (sizeof (child_data_t) == sizeof (long));

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, (void *) (unsigned long) data_p, NULL);
  assert_perror (errno);
  data = l;
  assert (data == l);
  assert (data == 42);

  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, (void *) ((0xdeadf00dUL << 32) | data_p),
	      NULL);
  assert (errno == EIO);
  assert (l == -1L);

  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, (void *) ((0xffffffffUL << 32) | data_p),
	      NULL);
  assert (errno == EIO);
  assert (l == -1L);

  return 0;
}

#endif	/* supported 64-bit arch */
