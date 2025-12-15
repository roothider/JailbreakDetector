#include <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <assert.h>
#include <libgen.h>

#define LOG printf


int gDesc = 0;
int gFiles = 0;
int gMachOs = 0;
int gSilces = 0;
int gCodeSigns = 0;
int gCodeSignBytes = 0;

int processMachO(const char* file, int (^handler)(int,uint64_t,size_t,void*))
{
    void* macho=NULL;
    int fd = open(file, O_RDONLY|O_NOFOLLOW_ANY);
    if(fd < 0) {
        fprintf(stderr, "open %s error:%d,%s\n", file, errno, strerror(errno));
        goto final;
    }
    
    gFiles++;
    
    struct stat st;
    if(stat(file, &st) < 0) {
        fprintf(stderr, "stat %s error:%d,%s\n", file, errno, strerror(errno));
        goto final;
    }
    
    LOG("file size = %lld\n", st.st_size);

    int mapflag = MAP_PRIVATE;
#ifdef MAP_RESILIENT_CODESIGN
    /* MAP_RESILIENT_CODESIGN only works with MAP_PRIVATE+(PROT_READ[|PROT_WRITE]) or MAP_SHARED+PROT_READ */
    mapflag |= MAP_RESILIENT_CODESIGN;
#endif
    macho = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, mapflag, fd, 0);
    if(macho == MAP_FAILED) {
        fprintf(stderr, "map %s error:%d,%s\n", file, errno, strerror(errno));
        goto final;
    }
    
    uint32_t magic = *(uint32_t*)macho;
    LOG("macho magic=%08x\n", magic);
    if(magic==FAT_MAGIC || magic==FAT_CIGAM) {
        gMachOs++;
        struct fat_header* fathdr = (struct fat_header*)macho;
        struct fat_arch* archdr = (struct fat_arch*)((uint64_t)fathdr + sizeof(*fathdr));
        int count = magic==FAT_MAGIC ? fathdr->nfat_arch : __builtin_bswap32(fathdr->nfat_arch);
        for(int i=0; i<count; i++) {
            uint32_t offset = magic==FAT_MAGIC ? archdr[i].offset : __builtin_bswap32(archdr[i].offset);
            uint64_t size = magic==FAT_MAGIC ? archdr[i].size : __builtin_bswap64(archdr[i].size);
            if(handler(fd, offset, size, (void*)((uint64_t)macho + offset)) < 0)
                goto final;
        }
    } else if(magic==FAT_MAGIC_64 || magic==FAT_CIGAM_64) {
        gMachOs++;
        struct fat_header* fathdr = (struct fat_header*)macho;
        struct fat_arch_64* archdr = (struct fat_arch_64*)((uint64_t)fathdr + sizeof(*fathdr));
        int count = magic==FAT_MAGIC_64 ? fathdr->nfat_arch : __builtin_bswap32(fathdr->nfat_arch);
        for(int i=0; i<count; i++) {
            uint64_t offset = magic==FAT_MAGIC_64 ? archdr[i].offset : __builtin_bswap64(archdr[i].offset);
            uint64_t size = magic==FAT_MAGIC_64 ? archdr[i].size : __builtin_bswap64(archdr[i].size);
            if(handler(fd, offset, size, (void*)((uint64_t)macho + offset)) < 0)
                goto final;
        }
    } else if(magic == MH_MAGIC_64) {
        gMachOs++;
        if(handler(fd, 0, st.st_size, (void*)macho) < 0)
            goto final;
    } else {
        fprintf(stderr, "unknown magic: %08x\n", magic);
        goto final;
    }

final:
    if(macho!=MAP_FAILED) munmap(macho, st.st_size);
    if(fd>=0) close(fd);

    return 0;
}

int findCodeSignature(struct mach_header_64* header, void(^handler)(void*, size_t))
{
    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {
                
        switch(lc->cmd) {
                
            case LC_CODE_SIGNATURE:
            {
                struct linkedit_data_command* sigCmd = (struct linkedit_data_command*)lc;
                handler((void*)((uint64_t)header + sigCmd->dataoff), sigCmd->datasize);
                break;
            }
        }

        /////////
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    return 0;
}

void writeMachOFileSig(NSString* path)
{
    static int index=1;
    static FILE* outfp = NULL;
    static FILE* sigfp = NULL;
    static NSMutableSet* jbsigs = nil;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        jbsigs = [NSMutableSet new];
        
        [NSFileManager.defaultManager removeItemAtPath:@"jbsigs" error:nil];
        
        mkdir("jbsigs", 0755);
        
        outfp = fopen("jbsigs.h", "w+");
        fprintf(outfp, "#include \"jbsigs/jbsigs-%d.h\"\n", index);
    });
    
    __block NSMutableString* result = [NSMutableString new];
    LOG("file: %s\n", path.fileSystemRepresentation);
    processMachO(path.fileSystemRepresentation, ^(int fd,uint64_t offset,size_t size, void* header) {
        gSilces++;
        findCodeSignature(header, ^(void* data, size_t size) {
            uint8_t hash[CC_SHA1_DIGEST_LENGTH]={0};
            CC_SHA1(data, (CC_LONG)size, hash);
            char hashstr[sizeof(hash)*2 + 1] = {0};
            for(int i=0; i<sizeof(hash)/sizeof(hash[0]); i++) {
                sprintf(hashstr+i*2, "%02x", hash[i]);
            }
            LOG("\tslice(%llx) hash: %s\n", offset, hashstr);
            
            if([jbsigs containsObject:@(hashstr)]) {
                LOG("hash already added, skip!\n");
                return;
            }
            [jbsigs addObject:@(hashstr)];
            
            gCodeSigns++;
            gCodeSignBytes+=size;
            
            if((gCodeSignBytes/index) > (1*1024*1024))
            {
                index++;
                fprintf(outfp, "#include \"jbsigs/jbsigs-%d.h\"\n", index);
                if(sigfp) {
                    fclose(sigfp);
                    sigfp=NULL;
                }
            }
            
            if(!sigfp) {
                char sigpath[PATH_MAX];
                snprintf(sigpath,sizeof(sigpath),"jbsigs/jbsigs-%d.h", index);
                sigfp = fopen(sigpath, "w+");
            }
            
            if(gDesc) fprintf(sigfp, "// %s, %llx\n", path.lastPathComponent.fileSystemRepresentation, offset);
            fprintf(sigfp, "JBSIGS(%ld, %s, ((uint8_t[]){\n", size, hashstr);
            for(int i=0; i<size; i++) {
                if (i % 16 == 0) {
                    if (i != 0) {
                        fprintf(sigfp, ",\n");
                    }
                    fprintf(sigfp, "\t");
                } else {
                    fprintf(sigfp, ", ");
                }
                fprintf(sigfp, "0x%02X", ((uint8_t*)data)[i]);
            }
            fprintf(sigfp, "\n}))\n\n");
        });
        return 0;
    });
}

int realmain(int argc, char * argv[])
{
    if(argc < 2) {
        printf("Usage: %s /path/to/jb/files/dir", getprogname());
        return -1;
    }
    
    if(argc >= 3) {
        gDesc = YES;
    }
    
    if(access(argv[1], F_OK) != 0) {
        LOG("invalid dir path: %s\n", argv[1]);
        return -1;
    }
    
    NSDirectoryEnumerator<NSURL *> *directoryEnumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:@(argv[1]) isDirectory:YES] includingPropertiesForKeys:nil options:0 errorHandler:nil];
    for(NSURL* file in directoryEnumerator) {
        writeMachOFileSig(file.path);
    }
    
    printf("total files=%d machos=%d silces=%d codesigns=%d bytes=%d wrote to jbsigs.h\n", gFiles, gMachOs, gSilces, gCodeSigns, gCodeSignBytes);
    
    return 0;
}

#ifndef __XCODE_IDE_TEST__
//clang -framework Foundation jbsigs_generator.m -o jbsigs_generator
int main(int argc, char * argv[])
{
    return realmain(argc, argv);
}
#endif
