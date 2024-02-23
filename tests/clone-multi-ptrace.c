/* Test case whether CLONE_PTRACE works right, "many threads" case.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* Trips fairly fast (less than a second) on a 2 CPU Itanium system
   with 2.6.18-118.el5 kernel.

   NB: if clone-ptrace.c testcase fails, don't bother debugging failures
   in this testcase. Deal with clone-ptrace.c first.  */

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
#include <asm/unistd.h> /* for __NR_exit */

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <sched.h>
#include <time.h>

#ifdef __ia64__
extern int __clone2 (int (*fn) (void *), void *child_stack_base,
		     size_t stack_size, int flags, void *arg, ...);
#define clone2 __clone2
#else
#define clone2(func, stack_base, size, flags, arg...) \
        clone (func, (stack_base) + (size), flags, arg)
#endif


/* Set to 1 in standalone runs, to see progress dots and messages.  */
#define TALKATIVE 0
#define DEFAULT_TESTTIME 2
#define THREAD_NUM 32


static pid_t child, grandchild[THREAD_NUM];
static char grandchild_seen[THREAD_NUM];

static int
grandchild_func (void *unused)
{
  /* _exit() would make ALL threads to exit.  We need rew syscall.  After the
     clone syscall it must call no glibc code (such as _dl_runtime_resolve).  */
  syscall (__NR_exit, 22);

  return 0;
}

static void
cleanup (void)
{
  int i;
  if (child > 0)
    {
      kill (child, SIGKILL);
      child = 0;
    }
  for (i = 0; i < THREAD_NUM; i++)
    if (grandchild[i] > 0)
      {
	kill (grandchild[i], SIGKILL);
	grandchild[i] = 0;
      }
  /* Wait for all killed children. Need this because we run test repeatedly -
     see main() and try_to_reproduce().  */
  while (waitpid (-1, NULL, __WALL) > 0)
    continue;
}

static void
handler_fail (int signo)
{
  cleanup ();
  signal (SIGABRT, SIG_DFL);
  assert (0);
}

void
try_to_reproduce (void)
{
  int status;
  pid_t pid;
  int grandchild_stop;
  int grandchild_trap;

  child = fork ();
  if (child == 0)
    {
      /* child */
      int i;
      errno = 0;
      ptrace (PTRACE_TRACEME, 0, (void *) 0, (void *) 0);
      assert_perror (errno);
      raise (SIGSTOP);
      assert_perror (errno);

      for (i = 0; i < THREAD_NUM; i++)
	/* NB: malloc gives sufficiently aligned buffer.
	   long buf[] does not! (on ia64).  */
	/* As seen in pthread_create(): */
	clone2 (grandchild_func, malloc (16 * 1024), 16 * 1024, 0
		| CLONE_VM
		| CLONE_FS
		| CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM
		/* | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID */
		| CLONE_PTRACE | 0	/* no signal to send on death */
		, NULL);
      /* We never exit in order to not appear in waitpid() */
      for (;;)
	sleep (999);
    }

  /* We are parent tracer */
  assert (child > 0);

  /* Child has stopped itself, checking.  */
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  /* Continue the child.  */
  errno = 0;
  ptrace (PTRACE_CONT, pid, (void *) 1, (void *) 0);
  assert_perror (errno);

  /* Catch grandchildren after clone().
     Restart each grandchild with PTRACE_SYSCALL once.
     When it comes back, do not restart it.
     We are looking for a grandchild which does NOT
     come back after PTRACE_SYSCALL but runs until exit().
     This seems to require the following conditions:
     threads > CPUs, kernel 2.6.18-118.el5, ia64.
     See https://bugzilla.redhat.com/show_bug.cgi?id=461456
     If it happens, we see less than THREAD_NUM threads
     trapping with SIGTRAP, this loop never finishes
     and then we see one thread exiting, not trapping.
   */
  memset (grandchild_seen, 0, sizeof (grandchild_seen));
  grandchild_stop = 0;
  grandchild_trap = 0;
  while (grandchild_stop < THREAD_NUM || grandchild_trap < THREAD_NUM)
    {
      int j;

      /* __WALL: want to see all children, even cloned ones */
      pid = waitpid (-1, &status, __WALL);
      assert (pid > 0);
      assert (pid != child);
      for (j = 0; j < THREAD_NUM; j++)
	if (pid == grandchild[j])
	  break;
      if (WIFEXITED (status))
	{
	  /* Here is it. This thread did not stop after PTRACE_SYSCALL!  */
#if TALKATIVE
	  if (j < THREAD_NUM)
	    fprintf (stderr, "pid %d exited (missed SIGTRAP)!\n", pid);
	  else			/* ...or did not even stop after CLONE_PTRACE */
	    fprintf (stderr, "pid %d exited (missed SIGSTOP)!\n", pid);
	  fprintf (stderr, "grandchildren with SIGSTOP:%d\n", grandchild_stop);
	  fprintf (stderr, "grandchildren with SIGTRAP:%d\n", grandchild_trap);
#endif
	  cleanup ();
	  exit (1);
	}
      assert (WIFSTOPPED (status));
      if (WSTOPSIG (status) == SIGSTOP)
	{
	  /* It must NOT be one of previous grandchildren */
	  assert (j == THREAD_NUM);
	  j = grandchild_stop;
	  grandchild[grandchild_stop] = pid;
	  grandchild_stop++;
	}
      else
	{
	  /* It must be one of previous grandchildren */
	  assert (WSTOPSIG (status) == SIGTRAP);
	  assert (j < THREAD_NUM);
	  grandchild_trap++;
	}
      errno = 0;
      if (grandchild_seen[j] == 0)
	{
	  errno = 0;
	  ptrace (PTRACE_SYSCALL, pid, (void *) 1, (void *) 0);
	  /* I've seen this too, very rarely.  */
	  if (errno)
	    {
#if TALKATIVE
	      fprintf (stderr, "cannot PTRACE_SYSCALL grandchild %d?!"
		       " errno: %m\n", pid);
#endif
	      cleanup ();
	      exit (1);
	    }
	  grandchild_seen[j] = 1;
	}
      /* Else: we already restarted it once with PTRACE_SYSCALL,
         now just keep it stopped.  */
    }

  /* Kill them all.  */
  cleanup ();
}

int
main (int ac, char *av[])
{
  int i;
  char *testtime = getenv ("TESTTIME");
  int testtime_i = (testtime ? atoi (testtime) : DEFAULT_TESTTIME);

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (testtime_i + 1);

  for (i = 0; i < testtime_i; i++)
    {
      time_t t = time (NULL);
      while (t == time (NULL))
	{
	  try_to_reproduce ();
#if TALKATIVE
	  putchar ('.');
#endif
	}
    }

  cleanup ();
  return 0;
}

#if TALKATIVE
#endif
