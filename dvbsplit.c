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

#include "dvbsplit.h"

#include <getopt.h>


static struct ts_program *progs_head = NULL;
static struct ts_es *es_head = NULL;
static char *dest = NULL;

void print_usage() {

	printf( "Usage : dvbsplit [options] [dest-folder]\n"
		"You must first tune to the right transponder by using an external application such as czap.\n"
		"\n"
		"Options :\n"
		" -a, --adapter=x        DVB adapter to use\n"
		" -n, --no-copy-pat-pmt  don't copy the original PAT and PMT in the output TS file\n"
		"\n"
		"dest-folder             destination folder for the TS files\n"
		"\n");
	return;

}

int main(int argc, char *argv[]) {

	int adapt = 0;
	int c;
	int copy_pat_pmt = 1;
	while (1) {
		static struct option long_options[] = {
			{ "adapter", 1, 0, 'a' },
			{ "no-copy-pat-pmt", 1, 0, 'n' },
			{ "help", 0, 0, 'h' },
			{ NULL, 0, 0, 0 },
		};
	
		char *args = "a:nh";


		c = getopt_long(argc, argv, args, long_options, NULL);

		if (c == -1)
			break;

		switch (c) {
			case 'a':
				if (sscanf(optarg, "%u", &adapt) != 1) {
					printf("Invalid adapter id \"%s\"\n", optarg);
					print_usage();
					return -1;
				}
				break;
			case 'c':
				copy_pat_pmt = 1;
				break;
			case 'h':
			default:
				print_usage();
				return -1;

				
		}
	}

	if (optind < argc)
		dest = argv[optind];


	// Open demux device
	char demux_dev[NAME_MAX + 1];
	snprintf(demux_dev, NAME_MAX, "/dev/dvb/adapter%u/demux0", adapt);
	
	int demux_fd = open(demux_dev, O_RDWR);
	if (demux_fd == -1) {
		printf("Unable to open demux device %s\n", demux_dev);
		return -1;
	}

	// Use a larger buffer
	if (ioctl(demux_fd, DMX_SET_BUFFER_SIZE, (unsigned long) DEMUX_BUFFER_SIZE) != 0) {
		printf("Unable to set a larger buffer for the demux device\n");
		return -1;
	}

	// Set filter to send all the TS stream with MPEG headers
	struct dmx_pes_filter_params filter;
	memset(&filter, 0, sizeof(struct dmx_pes_filter_params));
	filter.pid = PID_FULL_TS;
	filter.input = DMX_IN_FRONTEND;
	filter.output = DMX_OUT_TS_TAP;
	filter.pes_type = DMX_PES_OTHER;
	filter.flags = DMX_IMMEDIATE_START;

	if (ioctl(demux_fd, DMX_SET_PES_FILTER, &filter) != 0) {
		printf("Unable to set demuxer filter\n");
		return -1;
	}

	// Open the dvr device
	
	char dvr_dev[NAME_MAX];
	snprintf(dvr_dev, NAME_MAX, "/dev/dvb/adapter%u/dvr0", adapt);
	int dvr_fd = open(dvr_dev, O_RDONLY);
	if (dvr_fd == -1) {
		printf("Unable to open the dvr device %s\n", dvr_dev);
		return -1;
	}

	// Allocate the PAT parser
	
	dvbpsi_handle pat_parser = dvbpsi_AttachPAT(processPAT, NULL);

	uint8_t buff[MPEG_TS_PKT_LEN];
	int res = get_packet(dvr_fd, buff);

	while (res) {
		uint16_t pid = get_pid(buff);
		int processed = 0;
		if (pid == MPEG_NULL_PID) {
			// do nothing
			processed = 1;
		} else if (pid == 0) {
			if (copy_pat_pmt) {
				struct ts_program *tmp = progs_head;
				while (tmp) {
					if (!write_packet(tmp->fd, buff)) 
						return -1;
					tmp = tmp->next;
				}
			}
			dvbpsi_PushPacket(pat_parser, buff);
			processed = 1;
		}

		if (!processed) {
			struct ts_es *tmp = es_head;
			while (tmp) {
				if (pid == tmp->pid) {
					if (!write_packet(tmp->prog->fd, buff)) 
						return -1;
					processed = 1;
					break;
				}
				tmp = tmp->next;
			}
		}

		if (!processed) {
			struct ts_program *tmp = progs_head;
			while (tmp) {
				if (pid == tmp->pid) {
					if (copy_pat_pmt) {
						if (!write_packet(tmp->fd, buff))
							return -1;
					}
					dvbpsi_PushPacket(tmp->pmt_parser, buff);
					processed = 1;
					break;
				}
				tmp = tmp->next;
			}

		}


		res = get_packet(dvr_fd, buff);
	}

	dvbpsi_DetachPAT(pat_parser);

	return 0;
}

int get_packet(int fd, uint8_t *buff) {


	int ret;

restart_read:

	ret = 1;

	buff[0] = 0;

	while ((buff[0] != 0x47) && (ret > 0)) {
		ret = read(fd, buff, 1);
		if (ret < 0 && errno == EOVERFLOW) {
			printf("Buffer overflow in dvb card queue\n");
			goto restart_read;
		}
	}

	if (ret < 0 ) {
		printf("Read error 1 : %s\n", strerror(errno));
		return 0;
	}

	int i = MPEG_TS_PKT_LEN - 1;
	while ((i != 0) && (ret > 0)) {
		ret = read(fd, buff + MPEG_TS_PKT_LEN - i, i);
		if (ret < 0 && errno == EOVERFLOW) {
			printf("Buffer overflow in dvb card queue\n");
			goto restart_read;
		}
		if (ret >= 0) 
			i -= ret;
	}
	if (i != 0) {
		printf("Read error 2 : %s\n", strerror(errno));
		return 0;
	}

	return 1;

}

int write_packet(int fd, uint8_t *buff) {

	int ret = 1;

	int i = MPEG_TS_PKT_LEN;
	while ((i != 0) && (ret > 0)) {
		ret = write(fd, buff + MPEG_TS_PKT_LEN - i, i);
		if (ret >= 0)
			i -= ret;
	}

	if (i != 0) {
		printf("Write error\n");
		return 0;
	}

	return 1;

}

uint16_t get_pid(uint8_t *buff) {

	return ((uint16_t)(buff[1] & 0x1f) << 8) + (uint16_t)buff[2];
}


struct ts_program *alloc_prog(uint16_t pnum, uint16_t pid) {

	printf("New program 0x%X, PID 0x%X\n", pnum, pid);

	if (dest) {
		if (dest[strlen(dest) - 1] == '/')
			dest[strlen(dest) - 1] = 0;
	}
	
	struct tm tmp_time;
	time_t now = time(NULL);
	localtime_r(&now, &tmp_time);
	char *format = "%Y%m%d-%H%M%S";
	char time_str[16];
	strftime(time_str, sizeof(time_str), format, &tmp_time);


	char filename[NAME_MAX + 1];
	if (dest)
		snprintf(filename, NAME_MAX, "%s/%s-%u.ts", dest, time_str, pnum);
	else
		snprintf(filename, NAME_MAX, "%s-%u.ts", time_str, pnum);
	int fd = open(filename, O_WRONLY | O_CREAT, 0666);
	if (fd == -1) {
		printf("Unable to open %s\n", filename);
		return NULL;
	} 

	printf("File %s open\n", filename);
	struct ts_program *tmp = malloc(sizeof(struct ts_program));
	memset(tmp, 0, sizeof(struct ts_program));
	tmp->fd = fd;
	tmp->pnum = pnum;
	tmp->pid = pid;
	tmp->pmt_parser = dvbpsi_AttachPMT(pnum, processPMT, NULL);

	return tmp;
}

int cleanup_prog(struct ts_program *prog) {

	printf("Cleaning up progam 0x%X (PID 0x%X)\n", prog->pnum, prog->pid);
	if (prog->fd != -1)
		close(prog->fd);

	struct ts_es *tmp = es_head;
	while (tmp) {
		if (tmp->prog == prog) {
			if (tmp->prev)
				tmp->prev->next = tmp->next;
			else
				es_head = tmp->next;
			if (tmp->next)
				tmp->next->prev = tmp->prev;

			struct ts_es *tmp2 = tmp->next;
			free(tmp);
			tmp = tmp2;
			continue;

		}
		tmp = tmp->next;
	}

	dvbpsi_DetachPMT(prog->pmt_parser);

	free(prog);

	return 1;
}

void processPAT(void* p_zero, dvbpsi_pat_t* p_pat) {


	printf("New PAT : transport_stream_id : %d, version %d\n", p_pat->i_ts_id, p_pat->i_version);

	dvbpsi_pat_program_t* prog = p_pat->p_first_program;

	while (prog) {
		printf (" Prog %14d, PID : 0x%X\n", prog->i_number, prog->i_pid);

		struct ts_program *tmp = progs_head;

		while (tmp) {
			if (tmp->pnum == prog->i_number) {
				tmp->found = 1;
				break;
			}
			tmp = tmp->next;
		}

		if (!tmp) {
			tmp = alloc_prog(prog->i_number, prog->i_pid);
			tmp->found = 1;
			if (progs_head) {
				tmp->next = progs_head;
				progs_head->prev = tmp;
			}
			progs_head = tmp;

		}


		prog = prog->p_next;
	}

	struct ts_program *tmp = progs_head;
	while (tmp) {
		if (!tmp->found) {
			if (tmp->prev)
				tmp->prev->next = tmp->next;
			else
				progs_head = tmp->next;
			if (tmp->next)
				tmp->next->prev = tmp->prev;

			struct ts_program *tmp2 = tmp->next;
			cleanup_prog(tmp);
			tmp = tmp2;
			continue;

		}
		tmp->found = 0;
		tmp = tmp->next;
	}


	dvbpsi_DeletePAT(p_pat);

}

void processPMT(void* p_zero, dvbpsi_pmt_t* p_pmt) {

	printf("Processing PMT for prog number 0x%x\n", p_pmt->i_program_number);
	
	struct ts_program *prog = progs_head;
	while (prog) {
		if (prog->pnum == p_pmt->i_program_number)
			break;
		prog = prog->next;
	}

	if (!prog) {
		printf ("Program 0x%X not found in program list\n", p_pmt->i_program_number);
		return;
	}

	dvbpsi_pmt_es_t* p_es = p_pmt->p_first_es;
	while (p_es) {
		printf(" ES 0x%X, type 0x%X\n", p_es->i_pid, p_es->i_type);

		struct ts_es *tmp = es_head;

		while (tmp) {
			if (tmp->pid == p_es->i_pid) {
				tmp->found = 1;
				break;
			}
			tmp = tmp->next;
		}
		if (!tmp) {
				
			tmp = malloc(sizeof(struct ts_es));
			memset(tmp, 0, sizeof(struct ts_es));
			tmp->prog = prog;
			tmp->pid = p_es->i_pid;
			tmp->found = 1;
			if (es_head) {
				tmp->next = es_head;
				es_head->prev = tmp;
			}
			es_head = tmp;
		}

		p_es = p_es->p_next;
	}

	struct ts_es *tmp = es_head;
	while (tmp) {
		if (!tmp->found && tmp->prog == prog) {
			if (tmp->prev)
				tmp->prev->next = tmp->next;
			else
				es_head = tmp->next;
			if (tmp->next)
				tmp->next->prev = tmp->prev;

			struct ts_es *tmp2 = tmp->next;
			free(tmp);
			tmp = tmp2;
			continue;
		}
		tmp->found = 0;
		tmp = tmp->next;
	}

	dvbpsi_DeletePMT(p_pmt);

}

