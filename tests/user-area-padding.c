/* Test case for PTRACE_POKEUSR_AREA crashing while writing a padding space.
   s390-on-s390 and s390-on-s390x crashes, s390x-on-s390x has no padding space
   there.
   struct user_regs_struct {
   ...
       long unsigned int orig_gpr2;
   <- HERE are 4 aligned bytes on s390
       s390_fp_regs fp_regs;
   ...
   };

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
#include <sys/time.h>
#include <string.h>
#include <stddef.h>

#ifndef PTRACE_POKEUSR_AREA

int
main (void)
{
  return 77;
}

#else	/* PTRACE_POKEUSR_AREA */

/* The minimal alignment we sanity check.  */
#define REGALIGN 4

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

int
main (void)
{
  long l;
  int status, i;
  pid_t pid;
  union
    {
      struct user_regs_struct user;
      /* `per_struct per_info' is not preserved across POKE/PEEK.  */
      unsigned char byte[offsetof (struct user_regs_struct, per_info)];
    } u, u2;
  ptrace_area parea;
  size_t start = offsetof (struct user_regs_struct, orig_gpr2)
		 + sizeof (((struct user_regs_struct *) NULL)->orig_gpr2);
  size_t end = offsetof (struct user_regs_struct, fp_regs);

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  signal (SIGINT, handler_fail);
  i = alarm (10);
  assert (i == 0);

  /* s390x has no padding there, only s390 has.  */
  if (start == end)
    return 77;

  assert (start % REGALIGN == 0);
  assert (end % REGALIGN == 0);
  assert (end - start == REGALIGN);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);

    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);

      raise (SIGSTOP);
      assert (0);

    default:
      break;
    }

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);


  /* Initialize U with a pattern.  */
  for (i = start; i < end; i++)
    u.byte[i] = i;


  /* Poke U.  */
  parea.process_addr = (unsigned long) &u.byte[start];
  parea.kernel_addr = start;
  parea.len = end - start;
  l = ptrace (PTRACE_POKEUSR_AREA, child, &parea, NULL);
  assert (l == 0);

  /* Peek into U2.  */
  parea.process_addr = (unsigned long) &u2.byte[start];
  parea.kernel_addr = start;
  parea.len = end - start;
  l = ptrace (PTRACE_PEEKUSR_AREA, child, &parea, NULL);
  assert (l == 0);

  /* Verify if we read back zeroes despite we wrote there garbage.  */
  for (i = start; i < end; i++)
    if (u2.byte[i] != 0)
      break;
  if (i == end)
    return 0;

  /* Known FAIL if the padding area is read back how we wrote it as happens on
     a buggy RHEL-5.s390x kernel.  */
  if (memcmp (&u.byte[start], &u2.byte[start], end - start) == 0)
    return 1;

  assert (0);
  /* NOTREACHED */
}

#endif	/* PTRACE_POKEUSR_AREA */
