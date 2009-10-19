# packet-o-matic : split programs from a MPEG TS stream in multiple files
# Copyright (C) 2009 Guy Martin <gmsoft@tuxicoman.be>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA



#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([dvbsplit], [svn], [Guy Martin <gmsoft@tuxicoman.be>])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CC

AC_DISABLE_STATIC
AC_DEFUN([AC_PROG_CXX], [])
AC_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC


# Check for libdvbpsi

AC_CHECK_LIB([dvbpsi], [dvbpsi_AttachPAT, dvbpsi_AttachPMT], [], [AC_MSG_ERROR([Could not find libdvbpsi])])
AC_CHECK_HEADER([dvbpsi/dvbpsi.h], [], [AC_MSG_ERROR([Could not find libdvbpsi headers])])
AC_CHECK_HEADERS([linux/dvb/dmx.h linux/dvb/frontend.h], [], [AC_MSG_ERROR([Could not find linux DVB headers])])

AC_OUTPUT
