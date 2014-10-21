/* Copyright (c) 1999, 2000, 2001, 2005, 2006, 2010, 2011, 2012 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.de>

   The YP Server is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   version 2 as published by the Free Software Foundation.

   The YP Server is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with the YP Server; see the file COPYING. If
   not, write to the Free Software Foundation, Inc., 51 Franklin Street,
   Suite 500, Boston, MA 02110-1335, USA. */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif /* HAVE_ALLOCA_H */
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include "yppasswd.h"
#include "log_msg.h"
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif
#include "compat.h"

#ifndef CHECKROOT
/* Set to 0 if you don't want to check against the root password
   of the NIS master server. */
#define CHECKROOT 1
#endif

#ifndef _PATH_PASSWD
#define _PATH_PASSWD            "/etc/passwd"
#endif
#ifdef HAVE_GETSPNAM
#ifndef _PATH_SHADOW
#define _PATH_SHADOW            "/etc/shadow"
#endif
#endif
#ifndef _PATH_SHELLS
#define _PATH_SHELLS            "/etc/shells"
#endif

/* How often to retry locking the passwd file... */
#define MAX_RETRIES 5

char *path_passwd = _PATH_PASSWD;
char *path_passwd_tmp = NULL;
char *path_passwd_old = NULL;
#ifdef HAVE_GETSPNAM
char *path_shadow = _PATH_SHADOW;
char *path_shadow_tmp = NULL;
char *path_shadow_old = NULL;
#endif

/* Will be set by the main function */
char *external_update_program = NULL;

static bool_t adjuct_used = FALSE;

static int external_update_env (yppasswd *yppw);
static int external_update_pipe (yppasswd *yppw, char *logbuf);
static int update_files (yppasswd *yppw, char *logbuf, int *shadow_changed,
			 int *passwd_changed, int *chfn, int *chsh);

/* Argument validation. Avoid \n... (ouch).
   We can't use isprint, because people may use 8bit chars which
   aren't recognized as printable in the default locale. */
static int
validate_string (char *what, char *str)
{
  while (*str && *str != ':' && (unsigned char)*str >= 32)
    ++str
      ;
  if (*str == '\0')
    return 1;

  log_msg ("Invalid characters in %s argument: \"%s\"", what, str);

  return 0;
}

/* Check that nobody tries to change special NIS entries beginning
   with +/- and that all chracters are allowed. */
static inline int
validate_args (struct xpasswd *pw)
{
  if (pw->pw_name[0] == '-' || pw->pw_name[0] == '+')
    {
      log_msg ("attempt to modify NIS passwd entry \"%s\"", pw->pw_name);
      return 0;
    }

  return validate_string ("password", pw->pw_passwd)
    && validate_string ("shell", pw->pw_shell)
    && validate_string ("gecos", pw->pw_gecos);
}

static int
shell_ok (char *shell)
{
  char buffer[1024];
  FILE *fp;

  if ((fp = fopen (_PATH_SHELLS, "r")) == NULL)
    {
      log_msg ("can't open %s", _PATH_SHELLS);
      return 0;
    }
  while (fgets (buffer, sizeof (buffer), fp) != NULL)
    {
      buffer[sizeof (buffer) - 1] = '\0';
      if (!strncmp (buffer, shell, strcspn (buffer, " \t\n")))
        {
          fclose (fp);
          return 1;
        }
    }

  fclose (fp);
  return 0;
}

/* Read shadow file manually, to handle different colons count.
   When we use passwd.adjunct, shadow file contains 6 colons, but if
   we don't use passwd.adjunct, shadow file contains 8 colons.
   This function can handle both counts, but fgetspent doesn't */
static struct spwd *
fgetspent_adjunct(FILE *fp)
{
  static char line_buffer[1024];
  char *buffer_mark;
  struct spwd* result;
  int i, colons = 0;

  /* Reserve two bytes for theoretic colons */
  while (fgets(line_buffer, sizeof(line_buffer) - 2, fp) != NULL)
    {
      /* We don't need a new line character in the end */
      if ((buffer_mark = strchr(line_buffer, '\n')) != NULL)
          buffer_mark[0] = '\0';

      /* Skip commented or empty lines */
      if (line_buffer[0] == '\0' || line_buffer[0] == '#')
        continue;

      /* Count number of colons in the line */
      for (i = 0; line_buffer[i] != '\0'; ++i)
          if (line_buffer[i] == ':')
            ++colons;

      /* When we use passwd.adjunct, shadow file contains 6 colons,
         but we need 8 colons to properly parse the line, so we
         just add two colons to the end of the line */
      if (colons == 6)
        {
          strcat(line_buffer, "::");
          adjuct_used = TRUE;
        }

      /* Try to parse the line, if not success, read the next line */
      if ((result = sgetspent(line_buffer)) != NULL)
        return result;

    }
  return NULL;
}

/* Write an entry to the given stream.
   When we use passwd.adjunct, shadow file contains 6 colons, but if
   we don't use passwd.adjunct, shadow file contains 8 colons.
   This function can handle both counts, but putspent doesn't  */
static int
putspent_adjunct (const struct spwd *p, FILE *stream)
{
  int errors = 0;

  if (!adjuct_used)
    return putspent(p, stream);

  flockfile (stream);

  if (fprintf (stream, "%s:%s:::::", p->sp_namp, p->sp_pwdp ? p->sp_pwdp : "") < 0)
    ++errors;

  if (putc_unlocked ('\n', stream) == EOF)
    ++errors;

  funlockfile (stream);

  return errors ? -1 : 0;
}

/* Check if the password the user supplied matches the old one */
static int
password_ok (char *plain, char *crypted, char *root, char *logbuf)
{
  char *crypted_new;
  if (crypted[0] == '\0')
    return 1;
  crypted_new = crypt (plain, crypted);
  if (crypted_new == NULL)
    {
      log_msg ("crypt() call failed.", logbuf);
      return 0;
    }
  if (strcmp (crypted_new, crypted) == 0)
    return 1;
#if CHECKROOT
  crypted_new = crypt (plain, root);
  if (crypted_new == NULL)
    {
      log_msg ("crypt() call failed.", logbuf);
      return 0;
    }
  if (strcmp (crypted_new, root) == 0)
    return 1;
#endif

  return 0;
}

#ifdef HAVE_GETSPNAM
static inline int
is_allowed_to_change (const struct spwd *sp)
{
  long now;

  if (sp->sp_lstchg == 0 || sp->sp_lstchg == -1)
    return 1;

  now = time ((time_t *) 0) / (24L*3600L);

  if (sp->sp_min > sp->sp_max)
    return 0; /* Minimum is bigger then maximum */
  if (sp->sp_min > 0 && now <= (sp->sp_lstchg + sp->sp_min))
    return 0; /* It is to early to change password */
  if (sp->sp_inact >= 0 && sp->sp_max >= 0 &&
      now >= (sp->sp_lstchg + sp->sp_max + sp->sp_inact))
    return 0; /* It is to late to change password */

  return 1;
}
#endif

/*********************************************************************
 * The Update Handler                                                *
 *********************************************************************/

int *
yppasswdproc_pwupdate_1 (yppasswd *yppw, struct svc_req *rqstp)
{
  int shadow_changed = 0, passwd_changed = 0, chsh = 0, chfn = 0;
  int retries;
  static int res;                /* I hate static variables */
  char *logbuf;
  const struct sockaddr_in *rqhost = svc_getcaller (rqstp->rq_xprt);

  /* Be careful here with the debug option. You can see the old
     and new password in clear text !! */
  if (debug_flag)
    {
      log_msg ("yppasswdproc_pwupdate(\"%s\") [From: %s:%d]",
              yppw->newpw.pw_name,
              inet_ntoa (rqhost->sin_addr),
              ntohs (rqhost->sin_port));
      log_msg ("\toldpass..: %s", yppw->oldpass);
      log_msg ("\tpw_name..: %s", yppw->newpw.pw_name);
      log_msg ("\tpw_passwd: %s", yppw->newpw.pw_passwd);
      log_msg ("\tpw_gecos.: %s", yppw->newpw.pw_gecos);
      log_msg ("\tpw_dir...: %s", yppw->newpw.pw_dir);
      log_msg ("\tpw_shell.: %s", yppw->newpw.pw_shell);
    }

  res = 1; /* res = 1 means no success */

  logbuf = alloca (60 + strlen (yppw->newpw.pw_name) +
                   strlen (inet_ntoa (rqhost->sin_addr)));
  if (logbuf == NULL)
    {
      log_msg ("rpc.yppasswdd: out of memory");
      return &res;
    }

  sprintf (logbuf, "update %.12s (uid=%d) from host %s",
           yppw->newpw.pw_name, yppw->newpw.pw_uid,
	   inet_ntoa (rqhost->sin_addr));

  /* Check if somebody tries to make trouble with not allowed characters */
  if (!validate_args (&yppw->newpw))
    {
      log_msg ("%s failed", logbuf);
      return &res;
    }

  /* ATTENTION: The external program needs to do the password checking! */
  if (external_update_program)
    {
      struct passwd *pw;

      if ((pw = getpwnam (yppw->newpw.pw_name)) == NULL)
	{
	  log_msg ("user %s not found", yppw->newpw.pw_name);
	  return &res;
	}
      /* Do we need to update the GECOS information and are we allowed
	 to do it ? */
      chfn = (strcmp (pw->pw_gecos, yppw->newpw.pw_gecos) != 0);
      if (chfn && !allow_chfn)
	{
	  log_msg ("%s rejected", logbuf);
	  log_msg ("chfn not permitted");
	  return &res;
	}

      /* Do we need to update the shell adn are we allowed to do it ? */
      chsh = (strcmp (pw->pw_shell, yppw->newpw.pw_shell) != 0);
      if (chsh)
	{
	  if (!allow_chsh)
	    {
	      log_msg ("%s rejected", logbuf);
	      log_msg ("chsh not permitted");
	      return &res;
	    }
	  if (!shell_ok (yppw->newpw.pw_shell))
	    {
	      log_msg ("%s rejected", logbuf);
	      log_msg ("invalid shell: %s", yppw->newpw.pw_shell);
	      return &res;
	    }
	}

      if (x_flag)
        {
          res = external_update_pipe (yppw, logbuf);
          return &res;
        }
      else
        {
          res = external_update_env (yppw);
          if (res >= 2)
            return &res;
        }
      passwd_changed = 1; /* We don't know exactly what was changed. */
      shadow_changed = 1; /* So build everything new. */
    }
  else
    {
#ifdef HAVE_LCKPWDF
      /* Lock the passwd file. We retry several times. */
      retries = 0;
      while (lckpwdf () && retries < MAX_RETRIES)
	{
	  sleep (1);
	  ++retries;
	}

      if (retries == MAX_RETRIES)
	{
	  log_msg ("%s failed", logbuf);
	  log_msg ("password file locked");
	  return &res;
	}
#endif /* HAVE_LCKPWDF */

      res = update_files (yppw, logbuf, &shadow_changed, &passwd_changed,
			  &chfn, &chsh);

#ifdef HAVE_LCKPWDF
      ulckpwdf ();
#endif /* HAVE_LCKPWDF */
    }

  /* Fork off process to rebuild NIS passwd.* maps. */
  if (res == 0)
    /* The child (-E program) may exit(1), which means success, but
       don't run pwupdate. Bad, we tell the user that there was an
       error. Needs to be fixed later. */
    {
      int c;

      if ((c = fork ()) < 0)
        {
          /* Do NOT restore old password file. Someone else may already
           * be using the new one. */
          log_msg ("%s failed", logbuf);
          log_msg ("Couldn't fork map update process: %s", strerror (errno));
          return &res;
        }

      if (c == 0) /* We are the child */
        {
          if (shadow_changed)
            execlp (MAP_UPDATE_PATH, MAP_UPDATE, "shadow", NULL);
          else
            execlp (MAP_UPDATE_PATH, MAP_UPDATE, "passwd", NULL);
          log_msg ("Error: couldn't exec map update process: %s",
                  strerror (errno));
          exit (1);
        }

      log_msg ("%s successful.", logbuf);
      if (chsh || chfn)
	{
	  log_msg ("Shell %schanged (%s), GECOS %schanged (%s).",
		  chsh ? "" : "un", yppw->newpw.pw_shell,
		  chfn ? "" : "un", yppw->newpw.pw_gecos);
	}
    }

  return &res;
}

/*
  return code:
  0: success
  1: error
*/
static int
update_files (yppasswd *yppw, char *logbuf, int *shadow_changed,
	      int *passwd_changed, int *chfn, int *chsh)
{
  struct passwd *pw;
  struct spwd *spw = NULL;
  int gotit = 0;
  FILE *oldpf = NULL, *newpf = NULL, *oldsf = NULL, *newsf = NULL;
  struct stat passwd_stat, shadow_stat;
  char *rootpass = "x";

#if CHECKROOT
  if ((pw = getpwnam ("root")) != NULL)
    {
      if (strcmp (pw->pw_passwd, "x") == 0)
	{
#ifdef HAVE_GETSPNAM /* shadow password */
	  struct spwd *spw;

	  if ((spw = getspnam ("root")) != NULL)
	    {
	      rootpass = alloca (strlen (spw->sp_pwdp) + 1);
	      strcpy (rootpass, spw->sp_pwdp);
	    }
#endif /* HAVE_GETSPNAM */
	}
      else
	{
	  rootpass = alloca (strlen (pw->pw_passwd) + 1);
	  strcpy (rootpass, pw->pw_passwd);
	}
    }
#endif

  /* Open the passwd file for reading. We can't use getpwent and
     friends here. */
  if ((oldpf = fopen (path_passwd, "r")) == NULL)
    {
      log_msg ("%s failed", logbuf);
      log_msg ("Can't open %s: %m", path_passwd);
      return 1;
    }

  if (fstat (fileno (oldpf), &passwd_stat) < 0)
    {
      log_msg ("%s failed", logbuf);
      log_msg ("Can't stat %s: %m", path_passwd);
      fclose (oldpf);
      return 1;
    }

  /* Open a temp passwd file */
  if ((newpf = fopen (path_passwd_tmp, "w+")) == NULL)
    {
      log_msg ("%s failed", logbuf);
      log_msg ("Can't open %s: %m", path_passwd_tmp);
      fclose (oldpf);
      return 1;
    }
  chmod (path_passwd_tmp, passwd_stat.st_mode);
  if (chown (path_passwd_tmp, passwd_stat.st_uid, passwd_stat.st_gid) == -1)
    {
      log_msg ("chown failed: %s", strerror (errno));
      fclose (oldpf);
      fclose (newpf);
      unlink (path_passwd_tmp);
      return 1;
    }

#ifdef HAVE_GETSPNAM
  /* Open the shadow file for reading. */
  if ((oldsf = fopen (path_shadow, "r")) != NULL)
    {
      if (fstat (fileno (oldsf), &shadow_stat) < 0)
	{
	  log_msg ("%s failed", logbuf);
	  log_msg ("Can't stat %s: %m", path_shadow);
	  fclose (oldpf);
	  fclose (newpf);
	  fclose (oldsf);
	  return 1;
	}

      if ((newsf = fopen (path_shadow_tmp, "w+")) == NULL)
	{
	  int err = errno;
	  log_msg ("%s failed", logbuf);
	  log_msg ("Can't open %s.tmp: %s",
		   path_passwd, strerror (err));
	  fclose (oldsf);
	  fclose (newpf);
	  fclose (oldpf);
	  return 1;
	}
      chmod (path_shadow_tmp, shadow_stat.st_mode);
      if (chown (path_shadow_tmp, shadow_stat.st_uid,
		 shadow_stat.st_gid) == -1)
	{
	  log_msg ("chown failed", strerror (errno));
	  fclose (newsf);
	  fclose (oldsf);
	  fclose (newpf);
	  fclose (oldpf);
	  return 1;
	}
    }
#endif /* HAVE_GETSPNAM */

  /* Loop over all passwd entries */
  while ((pw = fgetpwent (oldpf)) != NULL)
    {
      /* check if this is the uid we want to change. A few
	 sanity checks added for consistency. */
      if ((uid_t)yppw->newpw.pw_uid == pw->pw_uid &&
	  (uid_t)yppw->newpw.pw_gid == pw->pw_gid &&
	  !strcmp (yppw->newpw.pw_name, pw->pw_name) && !gotit)
	{
	  ++gotit;

	  /* Check the password. At first check for a shadow password. */
	  if (oldsf != NULL &&
	      ((pw->pw_passwd[0] == 'x' && pw->pw_passwd[1] == '\0') ||
              (pw->pw_passwd[0] == '#' && pw->pw_passwd[1] == '#')))
	    {
#ifdef HAVE_GETSPNAM /* shadow password */
	      /* Search for the shadow entry of this user */
	      while ((spw = fgetspent_adjunct (oldsf)) != NULL)
		{
		  if (strcmp (yppw->newpw.pw_name, spw->sp_namp) == 0)
		    {
		      if (!password_ok (yppw->oldpass, spw->sp_pwdp, rootpass, logbuf))
			{
			  log_msg ("%s rejected", logbuf);
			  log_msg ("Invalid password.");
			  goto error;
			}
		      /* Password is ok, leave while loop */
		      break;
		    }
		  else if (putspent_adjunct (spw, newsf) < 0)
		    {
		      log_msg ("%s failed", logbuf);
		      log_msg ("Error while writing new shadow file: %m");
		      goto error;
		    }
		}
#endif /* HAVE_GETSPNAM */
	    }

	  /* We don't have a shadow password file or we don't find the
	     user in it. */
	  if (spw == NULL &&
	      !password_ok (yppw->oldpass, pw->pw_passwd, rootpass, logbuf))
	    {
	      log_msg ("%s rejected", logbuf);
	      log_msg ("Invalid password.");
	      goto error;
	    }

	  /*If the new password is not valid,
	    ignore it. User wishes to change GECOS or SHELL in this case. */
	  if (yppw->newpw.pw_passwd != NULL &&
	      !((yppw->newpw.pw_passwd[0] == 'x' ||
		 yppw->newpw.pw_passwd[0] == '*') &&
		yppw->newpw.pw_passwd[1] == '\0') &&
	      yppw->newpw.pw_passwd[0] != '\0')
	    {
#ifdef HAVE_GETSPNAM /* shadow password */
	      if (spw)
		{
		  /* test if password is expired */
		  if (spw->sp_pwdp[0] != '!')
		    {
		      if (is_allowed_to_change (spw))
			{
			  time_t now;

			  time(&now);
			  /* set the new passwd */
			  spw->sp_pwdp = yppw->newpw.pw_passwd;
			  spw->sp_lstchg = (long int)now / (24L*3600L);
			  *shadow_changed = 1;
			}
		      else
			{
			  log_msg ("%s rejected", logbuf);
			  log_msg ("now < minimum age for `%s'",
				  spw->sp_namp);
			  goto error;
			}
		    }
		  if (putspent_adjunct (spw, newsf) < 0)
		    {
		      log_msg ("%s failed", logbuf);
		      log_msg ("Error while writing new shadow file: %m");
		      *shadow_changed = 0;
		      goto error;
		    }

		  /* Copy all missing entries */
		  while ((spw = fgetspent_adjunct (oldsf)) != NULL)
		    if (putspent_adjunct (spw, newsf) < 0)
		      {
			log_msg ("%s failed", logbuf);
			log_msg ("Error while writing new shadow file: %m");
			*shadow_changed = 0;
			goto error;
		      }
		}
	      else /* No shadow entry */
#endif /* HAVE_GETSPNAM */
		{
		  /* set the new passwd */
		  pw->pw_passwd = yppw->newpw.pw_passwd;
		  *passwd_changed = 1;
		}
	    } /* end changing password */
	  else if (spw)
	    spw = NULL;

	  /* Handle chsh and chfn here*/

	  /* Do we need to update the GECOS information and are we allowed
	     to do it ? */
	  if (strcmp (pw->pw_gecos, yppw->newpw.pw_gecos) != 0)
	    {
	      if (!allow_chfn)
		{
		  log_msg ("%s rejected", logbuf);
		  log_msg ("chfn not permitted");
		  *passwd_changed = 0;
		  goto error;
		}
	      pw->pw_gecos = yppw->newpw.pw_gecos;
	      *chfn = 1;
	      *passwd_changed = 1;
	    }

	  /* Do we need to update the shell adn are we allowed to do it ? */
	  if (strcmp (pw->pw_shell, yppw->newpw.pw_shell) != 0)
	    {
	      if (!allow_chsh)
		{
		  log_msg ("%s rejected", logbuf);
		  log_msg ("chsh not permitted");
		  *passwd_changed = 0;
		  goto error;
		}
	      if (!shell_ok (yppw->newpw.pw_shell))
		{
		  log_msg ("%s rejected", logbuf);
		  log_msg ("invalid shell: %s", yppw->newpw.pw_shell);
		  *passwd_changed = 0;
		  goto error;
		}
	      pw->pw_shell = yppw->newpw.pw_shell;
	      *chsh = 1;
	      *passwd_changed = 1;
	    }
	} /* Found the entry */
      /* write the passwd entry to tmp file */
      if (putpwent (pw, newpf) < 0)
	{
	  int err = errno;
	  log_msg ("%s failed", logbuf);
	  log_msg ("Error while writing new password file: %s",
		   strerror (err));
	  *passwd_changed = 0;
	  break;
	}
      /* fflush (newpf); */
    } /* while */
 error:
  if (newpf) fclose (newpf);
  if (oldpf) fclose (oldpf);
  if (newsf) fclose (newsf);
  if (oldsf) fclose (oldsf);
  /* If one of them is non-NULL, an error ocured. */
  if (pw || spw)
    {
      unlink (path_passwd_tmp);
#ifdef HAVE_GETSPNAM
      unlink (path_shadow_tmp);
#endif /* HAVE_GETSPNAM */
      return 1;
    }
#ifdef HAVE_GETSPNAM
  if (*shadow_changed)
    {
      unlink (path_shadow_old);
      if (link (path_shadow, path_shadow_old) == -1)
	log_msg ("Cannot create backup file %s: %s",
		 path_shadow_old, strerror (errno));
      if (rename (path_shadow_tmp, path_shadow) == -1)
        {
          log_msg ("Cannot move temporary file %s to %s: %s",
                 path_shadow_tmp, path_shadow, strerror (errno));
          *shadow_changed = 0;
        }
    }
  else
    unlink (path_shadow_tmp);
#endif /* HAVE_GETSPNAM */

  if (*passwd_changed)
    {
      unlink (path_passwd_old);
      if (link (path_passwd, path_passwd_old) == -1)
	log_msg ("Cannot create backup file %s: %s",
		 path_passwd_old, strerror (errno));
      if (rename (path_passwd_tmp, path_passwd) == -1)
        {
          log_msg ("Cannot move temporary file %s to %s: %s",
                 path_passwd_tmp, path_passwd, strerror (errno));
          *passwd_changed = 0;
        }
    }
  else
    unlink (path_passwd_tmp);

  return !(*shadow_changed || *passwd_changed);
}

static int
external_update_env (yppasswd *yppw)
{
  int res = 0;
  int itmp = fork ();

  if (itmp)
    { /* Parent - try to get exit status */
      itmp = waitpid (itmp, &res, 0);

      if (itmp < 0)
        res = 2;
      else
        res = WEXITSTATUS(res);
    }
  else
    { /* Child - run external update program */
#if defined(HAVE_SETENV)
      setenv ("YP_PASSWD_OLD", yppw->oldpass, 1);
      setenv ("YP_PASSWD_NEW", yppw->newpw.pw_passwd, 1);
      setenv ("YP_USER", yppw->newpw.pw_name, 1);
      setenv ("YP_GECOS", yppw->newpw.pw_gecos, 1);
      setenv ("YP_SHELL", yppw->newpw.pw_shell, 1);
#else
#  error "Missing setenv(). Need porting."
#endif
      execlp (external_update_program, external_update_program, NULL);
      _exit (1); /* fall-through */
    }
  return res;
}

/*===============================================================*
 *
 * If rpc.yppasswdd is run with the -execute option, instead of
 * trying to manually modify the system passwd and/or shadow files,
 * we instead try to run the program designated by the -execute
 * option.
 *
 * We open a pair of pipes to communicate with the password-changing
 * program.  We write to the program's stdin a single line in the
 * form:
 *
 * <username> o:<oldpass> p:<password> s:<shell> g:<gcos>\n
 *
 * where <oldpass>, <password>, <shell>, and <gcos> are all expanded
 * into the information from the NIS passwd client.  The <oldpass> bit
 * is mandatory, and is to be used by the external program to validate
 * permissions to change the user's information.  The p:, s:, and g:
 * fields will be present if those attributes have changed.  If any of
 * those fields have not changed, we won't include that part of the
 * line, so if only the password has changed, we'll write something
 * like
 *
 * broccol o:<oldpass> p:e6GYrKvFKVBXw\n
 *
 * and if we just change the shell, it'll look like
 *
 * broccol o:<oldpass> s:/bin/tcsh\n
 *
 * In return, we read output from the program.  If the program sends
 *
 * OK[...]\n
 *
 * we return a code indicating a successful password information
 * change.  If the program does not emit OK as the first two
 * characters to its stdout, we interpret that as failure and we
 * report a failure to the NIS client.
 *
 * Note that the program executed is fully responsible for any
 * NIS build and propagation issues, as well as for checking
 * the submitted shell out for validity.
 *
 *===============================================================*/

static void
remove_password (char *str)
{
  char *ptr = strstr (str, " o:");

  if (ptr != NULL)
    {
      ptr+=3;
      while (*ptr && *ptr != ' ')
	*ptr++ = 'X';
    }

  ptr = strstr (str, " p:");
  if (ptr != NULL)
    {
      ptr+=3;
      while (*ptr && *ptr != ' ')
	*ptr++ = 'X';
    }
}

static int
external_update_pipe (yppasswd *yppw, char *logbuf)
{
  struct xpasswd *newpw;       /* passwd struct passed by the client */
  int res, pid, tochildpipe[2], toparentpipe[2];
  FILE *fp;
  char childresponse[1024];

  char *password = NULL;
  char *shell = NULL;
  char *gcos = NULL;

  char *parentmsg;
  size_t msglen;

  /* - */

  newpw = &yppw->newpw;
  res = 1;

  /*
   * determine what information we have to change
   */

  if (newpw->pw_passwd && *(newpw->pw_passwd))
    password = newpw->pw_passwd;

  if (allow_chsh && newpw->pw_shell && *(newpw->pw_shell))
    shell = newpw->pw_shell;

  if (allow_chfn && newpw->pw_gecos && *(newpw->pw_gecos))
    gcos = newpw->pw_gecos;

  if (!password && !shell && !gcos)
    {
      log_msg ("%s failed - no information to change", logbuf);
      return res;
    }

  /*
   * create the pipe we'll use to write to the stdin of the password
   * change utility we're going to call.
   */

  if (pipe(tochildpipe) < 0)
    {
      log_msg ("%s failed - couldn't create child pipe", logbuf);
      return res;
    }

  if (pipe(toparentpipe) < 0)
    {
      log_msg ("%s failed - couldn't create parent pipe", logbuf);
      return res;
    }

  if ((pid = fork()) < 0)
    {
      log_msg ("%s failed - couldn't fork", logbuf);
      return res;
    }

  if (pid == 0)
    {
      /*
       * the child executes this code..
       */

      /*
       * make the read side of the pipe our stdin for the password
       * change utilit
       */

      if (tochildpipe[0] != 0)
        {
          close(0);
          dup2(tochildpipe[0], 0);
        }

      /*
       * we're not going to write to ourselves
       */

      close(tochildpipe[1]);

      /*
       * make the write side of our end of the pipe stdout
       */

      if (toparentpipe[1] != 1)
        {
          close(1);
          dup2(toparentpipe[1], 1);
        }

      /*
       * we're not going to read from ourselves
       */

      close (toparentpipe[0]);

      execl (external_update_program, external_update_program, NULL);
      exit (1);
    }

  /*
   * the parent executes this code
   */

  close (tochildpipe[0]);
  close (toparentpipe[1]);

  /*
   * construct our message
   */
  msglen = strlen (yppw->newpw.pw_name) + strlen (yppw->oldpass) + 10;
  if (password)
    msglen += strlen (password) + 3;
  if (shell)
    msglen += strlen (shell) + 3;
  if (gcos)
    msglen += strlen (gcos) + 3;

  if ((parentmsg = malloc (msglen)) == NULL)
    {
      log_msg ("rpc.yppasswdd: out of memory");
      return res;
    }

  strcpy (parentmsg, yppw->newpw.pw_name);
  strcat (parentmsg, " o:");
  strcat (parentmsg, yppw->oldpass);
  strcat (parentmsg, " ");

  if (password)
    {
      strcat (parentmsg, "p:");
      strcat (parentmsg, password);
      strcat (parentmsg, " ");
    }

  if (shell)
    {
      strcat (parentmsg, "s:");
      strcat (parentmsg, shell);
      strcat (parentmsg, " ");
    }

  if (gcos)
    {
      strcat(parentmsg, "g:");
      strcat(parentmsg, gcos);
    }

  /*
   * write the message to our child
   */

  fp = fdopen(tochildpipe[1], "w");
  fprintf(fp, "%s\n", parentmsg);
  fclose(fp);

  /*
   * get output from the child
   */

  fp = fdopen(toparentpipe[0], "r");
  if (!fgets(childresponse, 1024, fp))
    {
      childresponse[0] = '\0';
      log_msg ("fgets() call failed or EOF.");
    }
  fclose(fp);

  if (!debug_flag)
    remove_password (parentmsg);

  if (strspn(childresponse, "OK") < 2)
    {
      log_msg ("%s failed.  Change request: %s", logbuf, parentmsg);
      log_msg ("Response was '%s'", childresponse);
      free (parentmsg);
      return res;
    }

  log_msg ("%s successful. Change request: %s", logbuf, parentmsg);

  free (parentmsg);
  res = 0;

  return res;
}
