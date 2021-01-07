/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2021 Harvard University
 * Copyright (C) 2020-2021 University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 * Author: Bogdan Stelea <bs17580@bristol.ac.uk>
 * Author: Soo Yee Lim <sooyee.lim@bristol.ac.uk>
 * Author: Xueyuan "Michael" Han <hanx@g.harvard.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <syslog.h>

#include "linux/provenance.h"
#include "camflow_bpf_id.h"

static uint32_t __boot_id = 0;
static uint32_t __machine_id = 0;

uint32_t get_boot_id(void){
    FILE *fptr;
    uint32_t boot_id = 1;
    int rc;

    if (__boot_id != 0)
        return __boot_id;

    fptr = fopen(CAMFLOW_BOOT_ID_FILE, "rb+");
    // Create the file if it does not exist
    if (!fptr) {
        fptr = fopen(CAMFLOW_BOOT_ID_FILE, "wb");
        if (!fptr) {
            syslog(LOG_ERR, "ProvBPF: Failed opening machine ID file.");
	    exit(-1);
	}
	fwrite(&boot_id, sizeof(uint32_t), 1, fptr);
    } else {
        rc = fread(&boot_id, sizeof(uint32_t), 1, fptr);
        if (rc < 0 && ferror(fptr))
	    exit(rc);
	boot_id += 1;
	fseek(fptr, 0, SEEK_SET);
	fwrite(&boot_id, sizeof(uint32_t), 1, fptr);
    }
    if (fptr)
	fclose(fptr);
    __boot_id=boot_id;
    return boot_id;
}

uint32_t get_machine_id(void){
    FILE *fptr;
    uint32_t machine_id;
    int rc;

    if (__machine_id != 0)
	return __machine_id;

    fptr = fopen(CAMFLOW_MACHINE_ID_FILE, "rb+");
    // Create the file if it does not exist
    if (!fptr) {
        fptr = fopen(CAMFLOW_MACHINE_ID_FILE, "wb");
	if (!fptr) {
	    syslog(LOG_ERR, "ProvBPF: Failed opening machine ID file.");
	    exit(-1);
	}
	srand(time(NULL) + gethostid());
	do {
	    machine_id = rand();
	} while (machine_id == 0);
	fwrite(&machine_id, sizeof(uint32_t), 1, fptr);
    } else {
        rc = fread(&machine_id, sizeof(uint32_t), 1, fptr);
	if (rc < 0 && ferror(fptr))
            exit(rc);
    }
    if (fptr)
        fclose(fptr);
    __machine_id=machine_id;
    return machine_id;
}
