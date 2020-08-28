#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "linux/provenance.h"
#include "camflow_bpf_id.h"

static uint32_t __boot_id = 0;
uint32_t get_boot_id(void){
  FILE *fptr;
  uint32_t boot_id=1;
  int rc;

  if (__boot_id!=0)
    return __boot_id;

  fptr = fopen(CAMFLOW_BOOT_ID_FILE, "rb+");
  if(!fptr) //if file does not exist, create it
  {
      fptr = fopen(CAMFLOW_BOOT_ID_FILE, "wb");
      if(!fptr){
        printf("Failed opening machine ID file.\n");
        exit(-1);
      }
      fwrite(&boot_id, sizeof(uint32_t), 1, fptr);
  }else{
    rc = fread(&boot_id, sizeof(uint32_t), 1, fptr);
    if(rc<0 && ferror(fptr))
        exit(rc);
    boot_id+=1;
    fseek(fptr, 0, SEEK_SET);
    fwrite(&boot_id, sizeof(uint32_t), 1, fptr);
  }
  if(fptr)
    fclose(fptr);
  __boot_id=boot_id;
  return boot_id;
}

static uint32_t __machine_id = 0;
uint32_t get_machine_id(void){
  FILE *fptr;
  uint32_t machine_id;
  int rc;

  if (__machine_id!=0)
    return __machine_id;

  fptr = fopen(CAMFLOW_MACHINE_ID_FILE, "rb+");
  if(!fptr) //if file does not exist, create it
  {
      fptr = fopen(CAMFLOW_MACHINE_ID_FILE, "wb");
      if(!fptr){
        printf("Failed opening machine ID file.\n");
        exit(-1);
      }
      srand(time(NULL)+gethostid());
      do {
        machine_id = rand();
      }while(machine_id==0);
      fwrite(&machine_id, sizeof(uint32_t), 1, fptr);
  }else{
    rc = fread(&machine_id, sizeof(uint32_t), 1, fptr);
    if(rc<0 && ferror(fptr))
        exit(rc);
  }
  if(fptr)
    fclose(fptr);
  __machine_id=machine_id;
  return machine_id;
}
