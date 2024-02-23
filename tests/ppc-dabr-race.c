/* Test case for PowerPC missed DABR (data watchpoint) on multiple threads.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* Bugreport posted at:
   http://ozlabs.org/pipermail/linuxppc-dev/2007-November/046951.html  */

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
#include <pthread.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>
#include <endian.h>

/* Number of threads to race; it should be probably about number-of-CPUs + 1.  */
#define THREADS 64

/* #define DEBUG */

#ifndef __powerpc__

int
main (void)
{
  return 77;
}

#else

#include <asm/unistd.h>
#include <unistd.h>
#define tgkill(pid, tid, sig) syscall (__NR_tgkill, (pid), (tid), (sig))
#define gettid() syscall (__NR_gettid)

#ifndef PTRACE_GET_DEBUGREG
# define PTRACE_GET_DEBUGREG	25
#endif
#ifndef PTRACE_SET_DEBUGREG
# define PTRACE_SET_DEBUGREG	26
#endif

static volatile long __attribute__((aligned(8))) variable = -1L;

static void setup (pid_t tid)
{
  long l;
  unsigned long dabr;

  dabr = (unsigned long) &variable;
  /* Sanity check the alignment of VARIABLE.  */
  assert ((dabr & 7) == 0);
  /* Catch all types of accesses.  */
  dabr |= 7;

  l = ptrace (PTRACE_SET_DEBUGREG, tid, NULL, (void *) dabr);
  if (l == -1)
    {
#ifdef DEBUG
      fprintf (stderr, "Your PowerPC hardware/CPU does not have the hardware"
		       " watchpoints support.\n");
#endif

      exit (77);
    }
  assert (l == 0);

#ifdef DEBUG
  l = ptrace (PTRACE_GET_DEBUGREG, tid, NULL, (void *) &dabr);
  assert (l == 0);
  errno = 0;
  l = ptrace (PTRACE_PEEKUSER, tid,
	      (void *) (unsigned long) offsetof (struct user, regs.nip),
	      NULL);
  assert_perror (errno);
  printf ("TID %d: DABR 0x%lx NIP 0x%lx\n", (int) tid, dabr, l);
#endif
}

static void check (pid_t tid)
{
#ifdef PTRACE_GETSIGINFO
  long l;
  siginfo_t siginfo;

  l = ptrace (PTRACE_GETSIGINFO, tid, NULL, &siginfo);
  assert (l == 0);

  assert (siginfo.si_signo == SIGTRAP);
  /* TRAP_HWBKPT */
  assert (siginfo.si_code == 4);
  assert ((unsigned long) siginfo.si_addr
	  == (~7UL & (unsigned long) &variable));
#endif /* PTRACE_GETSIGINFO */
}

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
  assert (0);
}

/* STARTED requires atomic access.  */
static volatile unsigned started;

static void *child_thread (void *data)
{
  pid_t tid = gettid ();

  __sync_add_and_fetch (&started, 1);

  /* We should stay in the syscall - better race probability.  */
  sleep (1);

#ifdef DEBUG
  printf ("TID %d: hitting the variable\n", (int) tid);
#endif

  /* Do not read the variable, write it atomically.  */
  variable = tid;

  for (;;)
    pause ();
  /* NOTREACHED */
  assert (0);
}

static void child_func (void)
{
  int i, thread_count;
  long l;

  for (thread_count = 0; thread_count < THREADS; thread_count++)
    {
      pthread_t thread;

      i = pthread_create (&thread, NULL, child_thread, NULL);
      assert (i == 0);
    }

  while (__sync_add_and_fetch (&started, 0) < THREADS);

  l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
  assert (l == 0);

  i = raise (SIGSTOP);
  assert (i == 0);

  /* We should never get continued by the parent tracer.  */
  /* NOTREACHED */
  assert (0);
}

int main (void)
{
  long l;
  int status, i;
  pid_t pid;
  char dirname[64];
  pid_t thread[THREADS];
  int thread_count, threadi;
  DIR *dir;
  struct dirent *dirent;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      child_func ();
      /* NOTREACHED */
      assert (0);
    default:
      break;
    }

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  snprintf (dirname, sizeof dirname, "/proc/%ld/task", (long) child);
  dir = opendir (dirname);
  assert (dir != NULL);

  thread_count = 0;
  while (errno = 0, dirent = readdir (dir))
    {
      char *s;
      pid_t tid;

      if (strcmp (dirent->d_name, ".") == 0)
        continue;
      if (strcmp (dirent->d_name, "..") == 0)
        continue;
      l = strtol (dirent->d_name, &s, 10);
      assert (l > 0 && l < LONG_MAX && (s == NULL || *s == 0));
      tid = l;
      assert (tid == l);
      if (tid == child)
        continue;
      assert (thread_count < THREADS);
      thread[thread_count++] = tid;

      l = ptrace (PTRACE_ATTACH, tid, NULL, NULL);
      assert (l == 0);

      pid = waitpid (tid, &status, __WCLONE);
      assert (pid == tid);
      assert (WIFSTOPPED (status));
      assert (WSTOPSIG (status) == SIGSTOP);
    }
  assert_perror (errno);
  assert (thread_count == THREADS);

  i = closedir (dir);
  assert (i == 0);

  for (threadi = 0; threadi < THREADS; threadi++)
    {
      pid_t tid = thread[threadi];

      setup (tid);

      l = ptrace (PTRACE_CONT, tid, NULL, NULL);
      assert (l == 0);
    }

  while (thread_count > 0)
    {
      pid_t tid;

      tid = waitpid (-1, &status, __WALL);

      assert (tid >= 0);
      /* There was no WNOHANG in this testcase.  */
      assert (tid != 0);

      assert (WIFSTOPPED (status));
      assert (WSTOPSIG (status) == SIGTRAP);

      /* Check we got stopped one of the spawned threads.  */
      for (threadi = 0; threadi < THREADS; threadi++)
	if (thread[threadi] == tid)
	  break;
      assert (threadi < THREADS);

      thread[threadi] = 0;
      thread_count--;

      check (tid);

      errno = 0;
      l = ptrace (PTRACE_PEEKDATA, tid, &variable, NULL);
      assert_perror (errno);
      /* We read more data than sizeof VARIABLE so shift it down to bit 0.  */
#if BYTE_ORDER == LITTLE_ENDIAN
      /* nop */
#elif BYTE_ORDER == BIG_ENDIAN
      l >>= ((sizeof l - sizeof variable) * 8);
#else
# error "!LITTLE_ENDIAN && !BIG_ENDIAN"
#endif
      variable = l;

#ifdef DEBUG
      printf ("variable found = %ld, caught TID = %ld\n", (long) variable,
	      (long) tid);
#endif

      if (variable != -1)
        {
#ifdef DEBUG
	  unsigned long dabr;

	  /* Stop it first to be able to read its DABR.  */
	  i = tgkill (child, variable, SIGSTOP);
	  assert (i == 0);

	  pid = waitpid (variable, &status, __WCLONE);
	  assert (pid == variable);
	  assert (WIFSTOPPED (status));
	  assert (WSTOPSIG (status) == SIGSTOP);

	  l = ptrace (PTRACE_GET_DEBUGREG, variable, NULL, (void *) &dabr);
	  assert (l == 0);
	  printf ("TID %d: DABR 0x%lx\n", (int) variable, dabr);

	  puts ("Variable got modified by a thread which has DABR still set!");
#endif	/* DEBUG */
	  return 1;
	}
    }

#ifdef DEBUG
  puts ("The kernel bug did not get reproduced - possibly increase THREADS.");
#endif

  return 0;
}

#endif	/* __powerpc__ */
