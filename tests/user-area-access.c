/* Test case for PTRACE_POKEUSR_AREA modifying only the requested range.
   s390* counterpart of the x86* testcase `user-regs-peekpoke.c'.

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

/* The minimal alignment we use for the random access ranges.  */
#ifdef __s390x__
# define REGALIGN 8
#elif defined __s390__
# define REGALIGN 4
#else
# error "Unexpected PTRACE_POKEUSR_AREA support"
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
  int start, end;
  size_t padding_start = (offsetof (struct user_regs_struct, orig_gpr2)
		      + sizeof (((struct user_regs_struct *) NULL)->orig_gpr2));
  size_t padding_end = offsetof (struct user_regs_struct, fp_regs);

  assert (padding_start % REGALIGN == 0);
  assert (padding_end % REGALIGN == 0);
  assert (padding_end - padding_start == REGALIGN	/* s390 */
	  || padding_end - padding_start == 0);		/* s390x */

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  signal (SIGINT, handler_fail);
  i = alarm (10);
  assert (i == 0);

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

  /* Fetch U2 from the inferior.  */
  parea.process_addr = (unsigned long) &u2.user;
  parea.kernel_addr = 0;
  parea.len = sizeof u.user;
  l = ptrace (PTRACE_PEEKUSR_AREA, child, &parea, NULL);
  assert (l == 0);
  for (i = padding_start; i < padding_end; i++)
    assert (u2.byte[i] == 0);

  /* Initialize U with a pattern.  */
  for (i = 0; i < sizeof u.byte; i++)
    u.byte[i] = i;
  /* Protect areas failing the poke on their arbitrary modifications.  */
  u.user.psw = u2.user.psw;
  u.user.fp_regs = u2.user.fp_regs;
  for (i = padding_start; i < padding_end; i++)
    u.byte[i] = u2.byte[i];	/* == 0 */


  /* Poke U.  */
  parea.process_addr = (unsigned long) &u.user;
  parea.kernel_addr = 0;
  parea.len = sizeof u.byte;
  l = ptrace (PTRACE_POKEUSR_AREA, child, &parea, NULL);
  assert (l == 0);

  /* Peek into U2.  */
  parea.process_addr = (unsigned long) &u2.user;
  parea.kernel_addr = 0;
  parea.len = sizeof u.byte;
  l = ptrace (PTRACE_PEEKUSR_AREA, child, &parea, NULL);
  assert (l == 0);

  /* Verify it matches.  */
  if (memcmp (&u.user, &u2.user, sizeof u.byte) != 0)
    return 1;


  /* Reverse the pattern.  */
  for (i = 0; i < sizeof u.byte; i++)
    u.byte[i] ^= -1;
  /* Protect areas failing the poke on their arbitrary modifications.  */
  u.user.psw = u2.user.psw;
  u.user.fp_regs = u2.user.fp_regs;
  for (i = padding_start; i < padding_end; i++)
    u.byte[i] = u2.byte[i];	/* == 0 */

  /* Poke U.  */
  parea.process_addr = (unsigned long) &u.user;
  parea.kernel_addr = 0;
  parea.len = sizeof u.byte;
  l = ptrace (PTRACE_POKEUSR_AREA, child, &parea, NULL);
  assert (l == 0);

  /* Peek into U2.  */
  parea.process_addr = (unsigned long) &u2.user;
  parea.kernel_addr = 0;
  parea.len = sizeof u.byte;
  l = ptrace (PTRACE_PEEKUSR_AREA, child, &parea, NULL);
  assert (l == 0);

  /* Verify it matches.  */
  if (memcmp (&u.user, &u2.user, sizeof u.byte) != 0)
    return 1;


  /* Now try poking arbitrary ranges and verifying it reads back right.
     We expect the U area is already a random enough pattern.  */
  for (start = 0; start + REGALIGN <= sizeof u.byte; start += REGALIGN)
    for (end = start + REGALIGN; end <= sizeof u.byte; end += REGALIGN)
      {
	for (i = start; i < end; i++)
	  u.byte[i]++;
	/* Protect areas failing the poke on their arbitrary modifications.  */
	u.user.psw = u2.user.psw;
	u.user.fp_regs = u2.user.fp_regs;
	for (i = padding_start; i < padding_end; i++)
	  u.byte[i] = u2.byte[i];	/* == 0 */

	/* Poke U.  */
	parea.process_addr = (unsigned long) &u.user + start;
	parea.kernel_addr = start;
	parea.len = end - start;
	l = ptrace (PTRACE_POKEUSR_AREA, child, &parea, NULL);
	assert (l == 0);

	/* Peek into U2.  */
	parea.process_addr = (unsigned long) &u2.user;
	parea.kernel_addr = 0;
	parea.len = sizeof u.byte;
	l = ptrace (PTRACE_PEEKUSR_AREA, child, &parea, NULL);
	assert (l == 0);

	/* Verify it matches.  */
	if (memcmp (&u.user, &u2.user, sizeof u.byte) != 0)
	  return 1;
      }


  /* Now try peeking arbitrary ranges and verifying it is the same.
     We expect the U area is already a random enough pattern.  */
  for (start = 0; start + REGALIGN <= sizeof u.byte; start += REGALIGN)
    for (end = start + REGALIGN; end <= sizeof u.byte; end += REGALIGN)
      {
	/* Peek into U2.  */
	parea.process_addr = (unsigned long) &u2.user + start;
	parea.kernel_addr = start;
	parea.len = end - start;
	l = ptrace (PTRACE_PEEKUSR_AREA, child, &parea, NULL);
	assert (l == 0);

	/* Verify it matches.  */
	if (memcmp (&u.user, &u2.user, sizeof u.byte) != 0)
	  return 1;
      }


  return 0;
}

#endif	/* PTRACE_POKEUSR_AREA */
