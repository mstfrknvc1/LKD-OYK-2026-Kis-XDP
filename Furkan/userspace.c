#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc,char **argv){
	const char * map_path = "/sys/fs/bpf/my_maps/drop_cnt";

	int map_fd = bpf_obj_get(map_path);
	if (map_fd<0){
	perror("bpf_obj_get");
	return 1 ;
}
	printf("harita acildi");
	__u32 key = 0;
	__u64 value;

    while(1){
	int ret = bpf_map_lookup_elem(map_fd,&key,&value);
	
	if ( ret != 0 ){
	    perror("bpf_map_lookup_elem");
            return 1;
}
	printf("bloklanan paketler %llu\r",value);
	fflush(stdout);
	sleep(1);
}
	return 0;
}
