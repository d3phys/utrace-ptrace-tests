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

#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stddef.h>
#include <errno.h>

/* #define DEBUG 1  */

#ifndef __i386__

int main (void)
{
  /* No #warning "i386 (or x86_64 with -m32) required"
     as we run with -Werror.   */
  return 77;
}

#else	/* __i386__ */

static pid_t child;

static void *start (void *arg)
{
  for (;;)
    pause ();
  /* NOTREACHED */
  assert (0);
  return arg;
}

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

/* Used only for PTRACE_GET_THREAD_AREA.  */
static int gs_to_idx (int gs)
{
  switch (gs)
    {
      /* kernel.x86  */
      case 0x33:
	return 6;
	/* NOTREACHED */
      /* kernel-smp-2.6.9-68.20.ELfsgs0.x86_64  */
      case 0x5b:
	return 11;
	/* NOTREACHED */
      /* kernel-2.6.25-0.88.rc3.git4.fc9.x86_64  */
      case 0x63:
	return 12;
	/* NOTREACHED */
    }
  assert (0);
  /* NOTREACHED */
}

static unsigned short local_get_gs (void)
{
  unsigned short gs;

  __asm__ __volatile__ ("movw %%gs, %0" : "=r" (gs));

  return gs;
}

int main (void)
{
  pthread_t thread1;
  pid_t got_pid;
  int i, status;
  long l;
  long debugreg0_orig, gs_orig;
  long debugreg0_new, gs_new;
  unsigned int desc[4];
  unsigned thread_area_orig;
  unsigned thread_area_new;

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);

  child = fork ();
  switch (child)
    {
      case -1:
        assert (0);
      case 0:
	i = pthread_create (&thread1, NULL, start, NULL);	/* create1 */
	assert (i == 0);

	/* Sanity check libpthread really set our local %gs.  */
	assert (local_get_gs () != 0);

	l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
	assert (l == 0);

	i = raise (SIGUSR1);
	assert (i == 0);

	for (;;)
	  pause ();
	/* NOTREACHED */
	assert (0);
      default:
        break;
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  debugreg0_orig = ptrace (PTRACE_PEEKUSER, child, (void *) (offsetof (struct user, u_debugreg[0])), NULL);
#ifdef DEBUG
  printf ("u_debugreg[0] == 0x%lx\n", debugreg0_orig);
#endif
  assert (debugreg0_orig == 0);
#ifdef DEBUG
  {
    long fs_orig = ptrace (PTRACE_PEEKUSER, child, (void *) (offsetof (struct user, regs.xfs)), NULL);

    printf ("fs == 0x%lx\n", fs_orig);
  }
#endif
  gs_orig = ptrace (PTRACE_PEEKUSER, child, (void *) (offsetof (struct user, regs.xgs)), NULL);
#ifdef DEBUG
  printf ("gs == 0x%lx\n", gs_orig);
#endif
  /* FIXME: RHEL-4.6 x86_64 fails here.  If CHILD's %gs would be 0 we would not
     earlier pass the CHILD's LOCAL_GET_GS assertion above.  */
  assert (gs_orig != 0);
/* Its definition location varies.  */
#ifndef PTRACE_GET_THREAD_AREA
#define PTRACE_GET_THREAD_AREA 25
#endif
  l = ptrace (PTRACE_GET_THREAD_AREA, child, (void *) gs_to_idx (gs_orig), &desc);
  assert (l == 0);
  thread_area_orig = desc[1];
#ifdef DEBUG
  printf ("thread_area == 0x%x\n", thread_area_orig);
#endif

#ifdef DEBUG
  printf ("u_debugreg[0] = 0x01010101\n");
#endif
  l = ptrace (PTRACE_POKEUSER, child, (void *) (offsetof (struct user, u_debugreg[0])), (void *) 0x01010101);
  assert (l == 0);
#if 0	/* Disallowed.  */
  printf ("gs = 0x02020202\n");
  l = ptrace (PTRACE_POKEUSER, child, (void *) (offsetof (struct user, regs.xgs)), (void *) 0x02020202);
  assert (l == 0);
#endif

  debugreg0_new = ptrace (PTRACE_PEEKUSER, child, (void *) (offsetof (struct user, u_debugreg[0])), NULL);
#ifdef DEBUG
  printf ("u_debugreg[0] == 0x%lx\n", debugreg0_new);
#endif
  gs_new = ptrace (PTRACE_PEEKUSER, child, (void *) (offsetof (struct user, regs.xgs)), NULL);
#ifdef DEBUG
  printf ("gs == 0x%lx\n", gs_new);
#endif
  l = ptrace (PTRACE_GET_THREAD_AREA, child, (void *) gs_to_idx (gs_orig), &desc);
  assert (l == 0);
  thread_area_new = desc[1];
#ifdef DEBUG
  printf ("thread_area == 0x%x\n", thread_area_new);
#endif

  assert (gs_new == gs_orig);
  assert (debugreg0_new == 0x01010101);
  assert (thread_area_new == thread_area_orig);

#ifdef DEBUG
  puts ("PASS");
#endif
  return 0;
}

#endif	/* __i386__ */
