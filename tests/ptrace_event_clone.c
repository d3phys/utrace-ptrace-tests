/* Simple PTRACE_EVENT_CLONE testcase.

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

/* On RHEL-4 it is present only in <linux/ptrace.h> in
   /lib/modules/`uname -r`/{build,source}.  */
#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS	0x4200
#endif
#ifndef PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE	0x00000008
#endif
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD	0x00000001
#endif
#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE	3
#endif

static int verbose;

#define VERBOSE(...) do { \
  if (verbose) \
    { \
      printf (__VA_ARGS__); \
      fflush (stdout); \
    } \
} while (0)


/* Enable this to compile real get_scno() [not all arches will compile] */
#if 0
static long
get_regs (pid_t pid, struct user_regs_struct *ur)
{
  long l;
  /* s390[x] defines PTRACE_GETREGS but it EIOs,
   * using PTRACE_GETREGS only if we have no PTRACE_PEEKUSR_AREA
   */
#ifndef PTRACE_PEEKUSR_AREA
# ifdef __sparc__
  l = ptrace (PTRACE_GETREGS, pid, ur, NULL);
# else
  l = ptrace (PTRACE_GETREGS, pid, NULL, ur);
# endif
#else
  ptrace_area parea;
  parea.process_addr = (unsigned long) ur;
  parea.kernel_addr = 0;
  parea.len = sizeof (*ur);
  l = ptrace (PTRACE_PEEKUSR_AREA, pid, &parea, NULL);
#endif
  return l;
}

static long
get_scno (pid_t pid)
{
  struct user_regs_struct regs;
  memset(&regs, 0xff, sizeof(regs));
  get_regs(pid, &regs);
# if defined __i386__
  return regs.orig_eax;
# elif defined __x86_64__
  return regs.orig_rax;
# else
#  error Add you arch here
# endif
}
#else
/* dummy get_scno() */
static long get_scno (pid_t pid) { return -1; }
#endif


static pid_t child, grandchild;

static int
grandchild_func (void *unused)
{
  _exit (22);
  return 0;
}

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  child = 0;
  if (grandchild > 0)
    kill (grandchild, SIGKILL);
  grandchild = 0;
  /* Wait for all killed children. */
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

/* https://bugzilla.redhat.com/show_bug.cgi?id=469693 */
/* "PTRACE_EVENT_CLONE not delivered when tracing system calls" */
static void
try_to_reproduce (void)
{
  int status;
  pid_t pid;

  child = fork ();
  if (child == 0)
    {
      /* child */
      /* need to do this before TRACEME, else brk syscalls may confuse parent */
      char *stack = malloc (16 * 1024);
      assert (stack != NULL);

      errno = 0;
      ptrace (PTRACE_TRACEME, 0, (void *) 0, (void *) 0);
      assert_perror (errno);
      // Prevent rt_sigprocmask() call called by glibc after raise().
      syscall (__NR_tkill, getpid (), SIGSTOP);
      assert_perror (errno);

      /* NB: malloc gives sufficiently aligned buffer.
         long buf[] does not! (on ia64).  */
      /* As seen in pthread_create(): */
      clone2 (grandchild_func, stack, 16 * 1024, 0
	      | CLONE_VM
	      | CLONE_FS
	      | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM
	      /* | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID */
	      | CLONE_PTRACE | 0	/* no signal to send on death */
	      , NULL);
      _exit (11);
    }

  /* We are parent tracer */
  errno = 0;
  assert (child > 0);

  /* Child has stopped itself, checking.  */
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  /* Request TRACECLONE notification */
  ptrace (PTRACE_SETOPTIONS, child, NULL,
	  PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE);
  assert_perror (errno);

  /* Execute clone2 */
  /* enter clone syscall */
  ptrace (PTRACE_SYSCALL, child, NULL, (void *) 0);
  assert_perror (errno);
  pid = waitpid (child, &status, __WALL);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == (SIGTRAP | 0x80));
  VERBOSE ("Entered syscall %ld\n", get_scno (pid));
  /* get PTRACE_EVENT_CLONE notification */
  ptrace (PTRACE_SYSCALL, child, NULL, (void *) 0);
  assert_perror (errno);
  pid = waitpid (child, &status, __WALL);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  if (WSTOPSIG (status) == (SIGTRAP | 0x80))
    { /* expected bug: we did not get expected PTRACE_EVENT_CLONE */
      VERBOSE ("Returned from syscall %ld\n", get_scno (pid));
      VERBOSE ("Expected PTRACE_EVENT_CLONE but got syscall stop report\n");
      cleanup ();
      exit (1);
    }
  assert (WSTOPSIG (status) == SIGTRAP);
  assert ((unsigned) (status) >> 16 == PTRACE_EVENT_CLONE);
  VERBOSE ("Got PTRACE_EVENT_CLONE\n");
  /* only after this waitpid(-1) below works */
  /* NB: we do not continue the child, it remains stopped after clone */

  /* Catch the grandchild */
  pid = waitpid (-1, &status, __WALL);
  assert (pid > 0);
  assert (pid != child);
  assert (WIFSTOPPED (status));
  grandchild = pid;
  assert (WSTOPSIG (status) == SIGSTOP);

  /* Kill them all */
  cleanup ();
}

int
main (int argc, char **argv)
{
  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  verbose = (argc - 1);
  alarm (1);

  try_to_reproduce ();

  return 0;
}
