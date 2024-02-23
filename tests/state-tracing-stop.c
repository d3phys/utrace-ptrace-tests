/* torvalds/linux-2.6.git 464763cf1c6df632dccc8f2f4c7e50163154a2c0 check-in
   correctly fixes `T (tracing stop)' to `t (tracing stop)'.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

#define _GNU_SOURCE 1
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

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
  signal (signo, SIG_DFL);
  raise (signo);
}

static const char *
proc_string (const char *filename, const char *line)
{
  FILE *f;
  static char buf[LINE_MAX];
  size_t line_len = strlen (line);

  f = fopen (filename, "r");
  if (f == NULL)
    {
      fprintf (stderr, "fopen (\"%s\") for \"%s\": %s\n", filename, line,
	       strerror (errno));
      exit (1);
    }
  while (errno = 0, fgets (buf, sizeof (buf), f))
    {
      char *s;

      s = strchr (buf, '\n');
      assert (s != NULL);
      *s = 0;

      if (strncmp (buf, line, line_len) != 0)
	continue;

      if (fclose (f))
	{
	  fprintf (stderr, "fclose (\"%s\") for \"%s\": %s\n", filename, line,
		   strerror (errno));
	  exit (1);
	}

      return &buf[line_len];
    }
  if (errno != 0)
    {
      fprintf (stderr, "fgets (\"%s\": %s\n", filename, strerror (errno));
      exit (1);
    }
  fprintf (stderr, "\"%s\": No line \"%s\" found.\n", filename, line);
  exit (1);
}

int
main (void)
{
  pid_t got_pid;
  int status, i;
  long l;
  char *filename;
  const char *state;
  const char pass[] = "t (tracing stop)";
  const char fail[] = "T (tracing stop)";

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);

    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);

      raise (SIGUSR1);
      _exit (42);

    default:
      break;
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  i = asprintf (&filename, "/proc/%lu/status", (unsigned long) child);
  assert (i > 0);

  state = proc_string (filename, "State:\t");

  if (strcmp (state, pass) == 0)
    return 0;
  if (strcmp (state, fail) == 0)
    return 1;

  fprintf (stderr, "Expected \"%s\", found \"%s\"!\n", pass, state);
  return 0;
}
