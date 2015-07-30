#ifndef _MEMDLOPEN_H_
#define _MEMDLOPEN_H_

int memdlopen_init(void);
void memdlopen(size_t size, void *data);

// 0x7ffff7de1256 <open_verify+102>:mov    rdx,r15
// 0x7ffff7de1259 <open_verify+105>:lea    rsi,[rbx+r14*1+0x8]
// 0x7ffff7de125e <open_verify+110>:sub    rdx,r14
// 0x7ffff7de1261 <open_verify+113>:callq   0x7ffff7df3200 <read>
//
// 0x7ffff7de1256 <open_verify+102>:0x4c 0x89 0xfa 0x4a 0x8d 0x74 0x33 0x8
// 0x7ffff7de125e <open_verify+110>:0x4c 0x29 0xf2 0xe8 0x9a 0x1f 0x1  0x0
#define read_pattern "\x4c\x89\xfa\x4a\x8d\x74\x33\x8\x4c\x29\xf2\xe8"

// 0x00007ffff7de220f <+1263>:mov    r8d,DWORD PTR [rbp-0xe4]
// 0x00007ffff7de2216 <+1270>:mov    rsi,QWORD PTR [rbp-0xe0]
// 0x00007ffff7de221d <+1277>:call   0x7ffff7df3310 <mmap64>
//
// 0x7ffff7de220f <_dl_map_object_from_fd+1263>:0x44 0x8b 0x85 0x24 0xff 0xff 0xff 0x48
// 0x7ffff7de2217 <_dl_map_object_from_fd+1271>:0x8b 0xb5 0x28 0xff 0xff 0xff 0xe8 0xee
#define mmap_pattern "\x44\x8b\x85\x1c\xff\xff\xff\x48\x8b\xb5\x20\xff\xff\xff\xe8"

// 0x00007ffff7de26c2 <+2466>:sub    rsp,rax
// 0x00007ffff7de26c5 <+2469>:mov    edi,r14d
// 0x00007ffff7de26c8 <+2472>:lea    r13,[rsp+0x47]
// 0x00007ffff7de26cd <+2477>:call   0x7ffff7df3380 <lseek64>
//
// 0x7ffff7de26c2 <_dl_map_object_from_fd+2466>:0x48 0x29 0xc4 0x44 0x89 0xff 0x4c 0x8d
// 0x7ffff7de26ca <_dl_map_object_from_fd+2474>:0x64 0x24 0x47 0xe8 0xae 0x0c 0x01 0x00
#define lseek_pattern "\x48\x29\xc4\x44\x89\xf7\x4c\x8d\x6c\x24\x47\xe8"

// 0x7ffff7de1d6a <_dl_map_object_from_fd+74>:mov    esi,r14d
// 0x7ffff7de1d6d <_dl_map_object_from_fd+77>:mov    edi,0x1
// 0x7ffff7de1d72 <_dl_map_object_from_fd+82>:mov    QWORD PTR [rbp-0xf0],rax
// 0x7ffff7de1d79 <_dl_map_object_from_fd+89>:call   0x7ffff7df3160 <__GI___fxstat>
//
// 0x7ffff7de1d6a <_dl_map_object_from_fd+74>:0x44 0x89 0xfe 0xbf 0x1 0x0 0x0 0x0
// 0x7ffff7de1d72 <_dl_map_object_from_fd+82>:0x48 0x89 0x85 0x18 0xff 0xff 0xff 0xe8
#define __fxstat_pattern "\x44\x89\xf6\xbf\x01\x00\x00\x00\x48\x89\x85\x10\xff\xff\xff\xe8"

// 0x7ffff7de25dc <_dl_map_object_from_fd+2236>:add    rax,QWORD PTR [r12]
// 0x7ffff7de25df <_dl_map_object_from_fd+2239>:mov    QWORD PTR [rbx+0x418],rax
// 0x7ffff7de25e6 <_dl_map_object_from_fd+2246>:mov    edi,DWORD PTR [rbp-0xe4]
// 0x7ffff7de25ec <_dl_map_object_from_fd+2252>:call   0x7ffff7df32f0 <close>
//
// 0x7ffff7de25dc <_dl_map_object_from_fd+2236>:0x48 0x3 0x3 0x48 0x89 0x83 0x18 0x4
// 0x7ffff7de25e4 <_dl_map_object_from_fd+2244>:0x0 0x0 0x8b 0xbd 0x24 0xff 0xff 0xff
// 0x7ffff7de25ec <_dl_map_object_from_fd+2252>:0xe8 0xff 0xc 0x1
//
#define close_pattern "\x49\x3\x4\x24\x49\x89\x84\x24\x18\x04\x00\x00\x8b\xbd\x1c\xff\xff\xff\xe8"

// 0x00007f9e03e7a21d <+45>:mov    rdi,QWORD PTR [rbp-0x40]
// 0x00007f9e03e7a221 <+49>:xor    eax,eax
// 0x00007f9e03e7a223 <+51>:mov    esi,0x80000
// 0x00007f9e03e7a228 <+56>:call   0x7f9e03e8c1e0 <open64>
//
// 0x7f9e03e7a21d <open_verify+45>:0x48 0x8b 0x7d 0xc0 0x31 0xc0 0xbe 0x0
// 0x7f9e03e7a225 <open_verify+53>:0x0 0x8 0x0 0xe8 0xb3 0x1f 0x1 0x0
#define open_pattern "\x48\x8b\x7d\xc0\x31\xc0\xbe\x00\x00\x08\x00\xe8"

#endif
