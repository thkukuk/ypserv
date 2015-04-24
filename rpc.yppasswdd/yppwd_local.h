/*
 * yppasswdd
 * Copyright 1994, 1995, 1996 Olaf Kirch, <okir@monad.swb.de>
 *
 * This program is covered by the GNU General Public License, version 2.
 * It is provided in the hope that it is useful. However, the author
 * disclaims ALL WARRANTIES, expressed or implied. See the GPL for details.
 *
 * This file was generated automatically by rpcgen from yppasswd.x, and
 * editied manually.
 */

#ifndef _YPPWD_LOCAL_H_
#define _YPPWD_LOCAL_H_

/* The server procedure invoked by the main loop. */
void   yppasswdprog_1(struct svc_req *rqstp, SVCXPRT *transp);

/* Handlers for the update RPC call, one for normal passwd files, and
 * one for shadow passwords.
 */
int *  yppasswdproc_pwupdate_1(yppasswd *yppw, struct svc_req *rqstp);
int *  yppasswdproc_spwupdate_1(yppasswd *yppw, struct svc_req *rqstp);

/*
 * Command-line options to yppasswdd.
 */
extern int	allow_chsh;
extern int	allow_chfn;
extern int	use_shadow;
extern int      x_flag;
extern char	*path_passwd;
extern char 	*path_passwd_tmp;
extern char 	*path_passwd_old;
extern char	*path_shadow;
extern char 	*path_shadow_tmp;
extern char 	*path_shadow_old;
extern char     *external_update_program;

/* This command is forked to rebuild the NIS maps after a successful
 * update. MAP_UPDATE0 is used as argv[0].
 */
#define MAP_UPDATE		"pwupdate"
#define MAP_UPDATE_PATH		YPBINDIR "/" MAP_UPDATE

#endif /* _YPPASSWD_H_ */
