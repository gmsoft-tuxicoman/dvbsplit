/*
 *  dvbsplit : split programs from a MPEG TS stream in multiple files
 *  Copyright (C) 2009 Guy Martin <gmsoft@tuxicoman.be>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>


#include <linux/dvb/dmx.h>
#include <linux/dvb/frontend.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <stdint.h>

#include <dvbpsi/dvbpsi.h>
#include <dvbpsi/psi.h>
#include <dvbpsi/pat.h>
#include <dvbpsi/descriptor.h>
#include <dvbpsi/pmt.h>
#include <dvbpsi/dr.h>


#define PID_FULL_TS     0x2000
#define MPEG_TS_PKT_LEN 188

#define MPEG_NULL_PID	0x1fff

#define DEMUX_BUFFER_SIZE 2097152 // 2Megs


struct ts_program {

	int fd;
	uint16_t pnum, pid;

	uint8_t found; // Used to check against the PAT

	dvbpsi_handle pmt_parser;

	struct ts_program *prev, *next;
};

struct ts_es {

	uint16_t pid;
	struct ts_program *prog;

	uint8_t found; // Used to check against PMT

	struct ts_es *prev, *next;


};

int get_packet(int fd, uint8_t *buff);
int write_packet(int fd, uint8_t *buff);
uint16_t get_pid(uint8_t *buff);
struct ts_program *alloc_prog(uint16_t pnum, uint16_t pid);
void processPAT(void* p_zero, dvbpsi_pat_t* p_pat);
void processPMT(void* p_zero, dvbpsi_pmt_t* p_pmt);

