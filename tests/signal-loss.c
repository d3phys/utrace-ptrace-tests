/* PTRACE_SYSCALL, kill (SIGINT), PTRACE_CONT, waitpid.
   waitpit should see SIGINT. Buugy kernels block on waitpid forever.

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

#include <signal.h>
#include <assert.h>
#include <dirent.h>
#include <limits.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>

/* On RHEL-4 it is present only in <linux/ptrace.h> in
   /lib/modules/`uname -r`/{build,source}.  */
#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS	0x4200
#endif
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD	0x00000001
#endif

static pid_t child;

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  child = 0;
  while (waitpid (-1, NULL, __WALL) > 0)
    continue;
}

static volatile int timeout_is_a_known_bug;
static volatile int timeout_is_ok;

static void
handler_fail (int signo)
{
  if (signo == SIGALRM)
    {
      if (timeout_is_ok)
	return;
      if (timeout_is_a_known_bug)
	exit (1);
    }

  cleanup ();
  signal (SIGABRT, SIG_DFL);
  assert (0);
}

/* https://bugzilla.redhat.com/show_bug.cgi?id=469684: */
/* "Signals not delivered when tracing system calls" */

/* If nothing strange happens, just returns.
 * If TALKATIVE is defined, print some debugging (mainly shows
 * that it is indeed *waitpid()* what blocks, not ptrace() etc).
 * Known bugs may print a message ifdef TALKATIVE, and exit (1).
 * The bug we are after can't do it, though, it's a hang, so
 * it trips via alarm() timing out.
 * New bugs are likely to trip asserts or alarm() timeout.
 */

/* Jan and me:
 *
 * > At that moment [after PTRACE_SYSCALL] you also asynchronously do
 * kill(2) there. kill(2) may come arbitrarily before or after
 * the inferior stops.
 *
 * True. This is done deliberately. When you strace a program and it is
 * being signaled by another process, you certainly can't control _when_
 * it will be signaled (when it is stopped or not). Thus ptrace should
 * work correctly in either case.
 *
 * > If you kill(2) it after the inferior stopped due to PTRACE_SYSCALL,
 * two different signals are generated at that moment, SIGINT and SIGTRAP|0x80.
 * You should pick up both signals by waitpid(2) otherwise one is left pending
 * and it all gets tricky.
 *
 * Yes. And testcase does exactly that. It waitpid's and collects SIGINTs until
 * it finally sees SIGTRAP|0x80. As you correctly point out,
 * it's not determinable how many SIGINTs we will get before
 * we see SIGTRAP|0x80. I saw from none to ~30. It's not a problem,
 * waitpid will collect them all, however many there are.
 *
 * What testcase is testing for is: as soon as we got SIGTRAP|0x80,
 * the very next stop should be SIGTRAP|0x80 too, and next one
 * should be SIGINT.
 *
 * On buggy kernels, second waitpid (which has to return second SIGTRAP|0x80)
 * does not return, it blocks.
 */
static void
reproduce (void)
{
  int status;
  int rc;
  pid_t pid;

  child = fork ();
  assert (child != -1);

  if (child == 0)
    {
      errno = 0;
      pause ();
      assert_perror (errno);
      assert (0);
    }

  rc = ptrace (PTRACE_ATTACH, child, NULL, NULL);
  assert (rc == 0);
  pid = waitpid (-1, &status, __WALL);
  assert (pid == child && WIFSTOPPED (status)
	  && WSTOPSIG (status) == SIGSTOP);
  rc = ptrace (PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESYSGOOD);
  assert (rc == 0);

  /* Enter the pause(2) syscall. Wait till inferior stops.  */
  errno = 0;
  rc = ptrace (PTRACE_SYSCALL, child, NULL, (void *) 0);
  assert_perror (errno);
  assert (rc == 0);
#ifdef TALKATIVE
  printf ("waitpid-enter...\n");
#endif
  errno = 0;
  pid = waitpid (child, &status, 0);
#ifdef TALKATIVE
  {
    const char *str1 = "";
    if (WIFSTOPPED (status) && WSTOPSIG (status) == SIGINT)
      str1 = " INT";
    if (WIFSTOPPED (status) && WSTOPSIG (status) == (SIGTRAP | 0x80))
      str1 = " TRAP|80";
    printf ("waitpid-enter: pid:%d status:%08x%s\n", pid, status, str1);
  }
#endif
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == (SIGTRAP | 0x80));

  /* Send signal. It will not kill the child because it is being traced,
   * and all signals are reported to tracer first. We never pass back
   * the signal through PTRACE_SYSCALL, thus it never reaches the child.
   * It should immediately report SIGINT back to us as would happen
   * if we would not be inside the pause(2) syscall because of the
   * PTRACE_SYSCALL above.
   */
  rc = kill (child, SIGINT);
  assert (rc == 0);

  /* At this point, waitpid should block, because inferior is stopped.
   * Signal just sent to it should not wake it up.
   * Check that this is true. (SIGALRM has SA_RESTART off,
   * waitpid will block for 1 second and SIGALRM will EINTR it).
   */
  timeout_is_ok = 1;
  alarm (1);
#ifdef TALKATIVE
  printf ("waitpid-kill...\n");
#endif
  errno = 0;
  pid = waitpid (child, &status, 0);
  if (errno != EINTR)
    assert_perror (errno);
  assert (pid == -1);
  assert (errno == EINTR);

  timeout_is_ok = 0;
  alarm (2);

  /* Leave the pause(2) syscall.  */
  errno = 0;
  rc = ptrace (PTRACE_CONT, child, NULL, (void *) 0);
  assert_perror (errno);
  assert (rc == 0);

  /* We should get our SIGINT now. */
  /* kernel 2.6.26.6-79.fc9.x86_64 timeouts here as SIGINT was lost
     and inferior's pause(2) did not get aborted.  */
  timeout_is_a_known_bug = 1;
#ifdef TALKATIVE
  printf ("waitpid-leave...\n");
#endif
  errno = 0;
  pid = waitpid (child, &status, 0);
  timeout_is_a_known_bug = 0;
#ifdef TALKATIVE
  {
    const char *str1 = "";
    if (WIFSTOPPED (status) && WSTOPSIG (status) == SIGINT)
      str1 = " INT";
    if (WIFSTOPPED (status) && WSTOPSIG (status) == (SIGTRAP | 0x80))
      str1 = " TRAP|80";
    printf ("waitpid-leave: pid:%d status:%08x%s\n", pid, status, str1);
  }
#endif
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGINT);
  timeout_is_a_known_bug = 0;
}

int
main (int argc, char **argv)
{
  struct sigaction act;

  setbuf (stdout, NULL);
  atexit (cleanup);

  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);
  /* SIGALRM is set up without SA_RESTART: */
  memset (&act, 0, sizeof act);
  sigemptyset (&act.sa_mask);
  act.sa_handler = handler_fail;
  sigaction (SIGALRM, &act, NULL);

  alarm (2);
  reproduce ();
  alarm (0);
  cleanup ();

  return 0;
}
