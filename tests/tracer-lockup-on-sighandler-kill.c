/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.
   
   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* Removing the child->parent output/pipes make the bug unreproducible.  */

/* Looks buggy to me.
   Problematic places are marked with //bug? XXX comments.  */

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

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

/* WARNING: The real testing count is unbound.
   Seen hit at 580000 - about 2.5 minutes.  */
#define DEFAULT_TESTTIME (5 * 60) 	/* seconds */

#if    defined(__x86_64) || defined(__x86_64__) \
    || defined(__amd64)  || defined(__amd64__)
#define PC_OFFSET 128
#elif defined(__i386) || defined(__i386__)
#define PC_OFFSET 48
#endif

#ifdef PC_OFFSET

int hit_do_nothing = 0;

void
do_nothing(int signum) {
   hit_do_nothing = 1;
   return;
}

void
report_error(char * name, char * func) {
   int errnum = errno;
   printf("ERR: %s %s call failed: %s (errno = %d)\n",
           name, func, strerror(errnum), errnum);
   fflush(stdout);
}

void
fatal_error(char * name, char * func) {
   report_error(name, func);
   exit(2);
}

// On some versions of linux kill() isn't good enough to kill a debugged
// child. This routine does both a PTRACE_KILL and a kill() to make
// doubly sure :-).

void
kill_kid_dead(pid_t kid) {
   ptrace(PTRACE_KILL, kid, 0, 0);
   kill(kid, 9);
}

char *
status_string(int kidstat) {
   static char rval[512];
   if (WIFEXITED(kidstat)) {
      if (WEXITSTATUS(kidstat) == 0) {
         sprintf(rval, "exited normally");
      } else {
         sprintf(rval, "exited with status %d", WEXITSTATUS(kidstat));
      }
   } else if (WIFSIGNALED(kidstat)) {
      sprintf(rval, "terminated with signum %d", WTERMSIG(kidstat));
   } else if (WIFSTOPPED(kidstat)) {
      sprintf(rval, "stopped with signum %d", WSTOPSIG(kidstat));
   } else {
      sprintf(rval, "unrecognized status %#x", kidstat);
   }
   return rval;
}

// Single step a child and pass in a signal. See if we wind up in the handler
// or if the handler runs, then we step.
//
void
test_signalstep() {
   pid_t debugged_kid = fork();
   if (debugged_kid == 0) {

      int i;
      int x;

      // This is the child. It wants to be debugged, so it needs to
      // say so.

      if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
         fatal_error("test_signalstep child", "ptrace(PTRACE_TRACEME)");
      }
//bug? do we stop here or not?
// if not, we would stop at kill _unless_ parent,
// which races with us, gets to us faster...

      struct sigaction act;
      memset((void *)&act, 0, sizeof(act));
      act.sa_handler = do_nothing;
      if (sigaction(SIGUSR1, &act, NULL) == -1) {
         fatal_error("test_signalstep child", "sigaction(SIGUSR1)");
      }
      if (kill(getpid(), SIGUSR1) == -1) {
         fatal_error("test_signalstep child", "kill(SIGUSR1)");
      }

      hit_do_nothing = 0;
//bug? gcc can optimize it out totally - x is unused.
      x = 0;
      for (i = 0; i < 1000; ++i) {
         x = x + i;
      }

      exit(0);
   } else if (debugged_kid == (pid_t)-1) {
      fatal_error("test_signalstep", "fork()");
   } else {

      int i;

      int waitstat;
      if (waitpid(debugged_kid, &waitstat, WUNTRACED|__WALL) != debugged_kid) {
         fatal_error("test_signalstep", "waitpid()");
      }
//bug? we should expect a specific state here, which one?
// why we don't test for it and abort if we see something different?
// IIUC it must be "stopped by SIGUSR1", otherwise code below
// makes no sense.
      printf("INFO: test_signalstep pid %d status: %s\n",
             debugged_kid, status_string(waitstat));
      fflush(stdout);

      // Now single step the process a few times to well past the
      // kill() where it sent itself a SIGUSR1.

//... "SIGUSR1 is not injected back, so kill() turns into no-op", right? */

      for (i = 0; i < 3; ++i) {
         if (ptrace(PTRACE_SINGLESTEP, debugged_kid, 0, 0) == -1) {
            fatal_error("test_signalstep", "ptrace(PTRACE_SINGLESTEP)");
         }
         if (waitpid(debugged_kid, &waitstat, WUNTRACED|__WALL) != debugged_kid) {
            fatal_error("test_signalstep", "waitpid()");
         }
         printf("INFO: test_signalstep pid %d status: %s\n",
                debugged_kid, status_string(waitstat));
         fflush(stdout);
      }

      // Now single step, passing the SIGUSR1 signal and see if we wind up
      // at the signal handler, or at the next instruction.

      if (ptrace(PTRACE_SINGLESTEP, debugged_kid, 0, SIGUSR1) == -1) {
         fatal_error("test_signalstep", "ptrace(PTRACE_SINGLESTEP)");
      }
      if (waitpid(debugged_kid, &waitstat, WUNTRACED|__WALL) != debugged_kid) {
         fatal_error("test_signalstep", "waitpid()");
      }
      printf("INFO: test_signalstep pid %d status: %s\n",
             debugged_kid, status_string(waitstat));
      fflush(stdout);

      // Where is PC?

      long pcval = ptrace(PTRACE_PEEKUSER, debugged_kid, (void *)PC_OFFSET, 0);
      if (pcval == -1) {
         fatal_error("test_signalstep", "ptrace(PTRACE_PEEKUSER)");
      }
      printf("INFO: test_signalstep pid %d PC = 0x%lx\n",
             debugged_kid, pcval);
      if (((unsigned long)pcval) == (unsigned long)&do_nothing) {
         printf("DEF: STEP_INTO_HANDLER=1\n");
      } else {
         printf("DEF: STEP_INTO_HANDLER=0\n");
      }
      printf("INFO: calling kill_kid_dead(%d)\n", debugged_kid);
      fflush(stdout);
      kill_kid_dead(debugged_kid);
      printf("INFO: returned from kill_kid_dead(%d)\n", debugged_kid);
      fflush(stdout);

      // If this waitpid() call isn't done, sometimes I hang
      // forever eating 100% of a cpu.

#ifdef DO_NOT_HANG
      if (waitpid(debugged_kid, &waitstat, WUNTRACED|__WALL) != debugged_kid) {
         fatal_error("test_signalstep", "waitpid()");
      }
#endif
   }
}

int
main(int argc, char ** argv) {
   char *testtime = getenv ("TESTTIME");
   time_t testend = time (NULL) + (testtime != NULL ? atoi (testtime)
						    : DEFAULT_TESTTIME);
   unsigned long loops;

   // We don't want any nasy signals when children exit or pipes
   // close abnormally.

   sigset_t maskoff;
   sigemptyset(&maskoff);
   sigaddset(&maskoff, SIGCHLD);
   sigaddset(&maskoff, SIGPIPE);
   sigprocmask(SIG_BLOCK, &maskoff, NULL);

   // But I do want SIGUSR1 signals.

   sigemptyset(&maskoff);
   sigaddset(&maskoff, SIGUSR1);
   sigprocmask(SIG_UNBLOCK, &maskoff, NULL);

   char buf[10000];
   int buflen;
#if 0
   int runnum = 1;
#endif
   unsigned long bad = 0;

   loops = 0;
   do {

      int p[2];
      if (pipe(p) != 0) {
         report_error("test_signalstep", "pipe()");
         exit(2);
      }
      fflush(stdout);
      fflush(stderr);

      // Keep running test in a new kid till one of 'em gets hung...

      buflen = 0;
      pid_t kid = fork();
      if (kid == (pid_t)-1) {
         report_error("test_signalstep", "fork()");
         close(p[0]);
         close(p[1]);
         exit(2);
      }
      if (kid == 0) {

         // In the child, we want to swap in the p[1] file descriptor
         // as stdout and stderr so the parent can accumulate anything
         // we have to say by reading p[0]

         close(p[0]);
         if (dup2(p[1], fileno(stdout)) != fileno(stdout)) {
            exit(1);
         }
         if (dup2(p[1], fileno(stderr)) != fileno(stderr)) {
            exit(2);
         }
         close(p[1]);

         // Now run the test

         test_signalstep();

         // And exit from the child normally (if we get back here :-)

         exit(0);
      } else {

         // In this parent, all we do is read p[0] and accumulate it in
         // buf. However, we expect to see an eof within a few seconds, or
         // we assume the test is hung.

         close(p[1]);
         for ( ; ; ) {
            fd_set readfd;
            struct timeval tmout;
            FD_ZERO(&readfd);
            FD_SET(p[0], &readfd);
            memset((void *)&tmout, 0, sizeof(tmout));
            tmout.tv_sec = 10;     // 10 seconds should be an etrnity...
            int selstat = select(p[0] + 1, &readfd, NULL, NULL, &tmout);
            if (selstat == 0) {
               printf("We have a weiner!\n"
                      "The test_signalstep child pid %d is apparently hung.\n"
                      "The bug has been reproduced!\n", kid);
               buf[buflen] = '\0';
               printf("Accumulated output from test:\n%s\n", buf);
               fflush(stdout);
               exit(2);
            } else if (selstat == -1) {
               report_error("test_signalstep", "select()");
//bug? do we leak live stopped grandchildren?
               kill(kid, 9);
               exit(2);
            } else {
               int readlen = read(p[0], &buf[buflen], sizeof(buf) - buflen);
               if (readlen == 0) {
                  // EOF - kid must have exited normally - no hang
                  break;
               } else if (readlen == -1) {
                  report_error("test_signalstep", "read()");
//bug? do we leak live stopped grandchildren?
                  kill(kid, 9);
                  exit(2);
               }
               buflen += readlen;
            }
         }
         close(p[0]);
         int kidstat;
         pid_t waitstat = waitpid(kid, &kidstat, 0);
         if (waitstat == kid) {
            if (WIFEXITED(kidstat) && (WEXITSTATUS(kidstat) == 0)) {
#if 0
               printf("INFO: %s: OK run # %d\n", "test_signalstep", runnum++);
               fflush(stdout);
#endif
            } else {
               printf("ERR: %s after %lu iterations: %s\n", "test_signalstep", loops, status_string(kidstat));
               fflush(stdout);
               ++bad;
            }
         } else {
            report_error("test_signalstep", "waitpid()");
            exit(2);
         }
      }
      loops++;
   } while (time (NULL) < testend);

   if (bad)
     {
       printf ("%lu bad in %lu iterations: %.2f%%\n",
               bad, loops, 100.0 * bad / loops);
       return 1;
     }

   return 0;
}

#else	/* !PC_OFFSET */

int main (void)
{
  return 77;
}
#endif	/* !PC_OFFSET */
