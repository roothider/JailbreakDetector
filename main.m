#import <UIKit/UIKit.h>
#include <mach/mach.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>
#include <dlfcn.h>
extern char**environ;

//Don't try to patch/hook me, it's a Kids's trick!

#define LOG(...) printf(__VA_ARGS__)

void detect_rootlessJB()
{
    if(access("/var/jb", F_OK)==0) {
        LOG("rootless JB found!\n");
    }
    
    if(access("/private/preboot/jb", F_OK)==0) {
        LOG("Fugu15 JB found!\n");
    }

    char* xinafiles[] = {
        "/var/containers/Bundle/dylib",
        "/var/containers/Bundle/xina",
        "/var/mobile/Library/Preferences/com.xina.blacklist.plist",
    };
    
    for(int i=0; i<sizeof(xinafiles)/sizeof(xinafiles[0]); i++) {
        if(access(xinafiles[i], F_OK)==0) {
            LOG("xina jb file found: %s\n", xinafiles[i]);
        }
    }
    
    char* varfiles[] = {
        "apt","bin","bzip2","cache","dpkg","etc","gzip","lib","Lib","libexec","Library","LIY","Liy","newuser","profile","sbin","sh","share","ssh","sudo_logsrvd.conf","suid_profile","sy","usr","zlogin","zlogout","zprofile","zshenv","zshrc", "master.passwd"
    };
    for(int i=0; i<sizeof(varfiles)/sizeof(varfiles[0]); i++) {
        char path[PATH_MAX];
        snprintf(path,sizeof(path),"/var/%s",varfiles[i]);
        if(access(path, F_OK)==0) {
            LOG("xina jb file found: %s\n", path);
        }
    }
}

void detect_kernBypass()
{
    if(access("/private/var/MobileSoftwareUpdate/mnt1/System", F_OK)==0)
    {
        LOG("kernBypass installed!\n");
    }
}

void detect_chroot()
{
    struct statfs s={0};
    statfs("/", &s);
    if(strcmp("/", s.f_mntonname)!=0) {
        LOG("chroot found! %s\n", s.f_mntonname);
    }
}

void detect_mount_fs()
{
    struct statfs * ss=NULL;
    int n = getmntinfo(&ss, 0);
    for(int i=0; i<n; i++) {
        //LOG("mount %s %s : %s : %x,%x\n", ss[i].f_fstypename, ss[i].f_mntonname, ss[i].f_mntfromname, ss[i].f_flags, ss[i].f_flags_ext);
        
        if(strcmp("/", ss[i].f_mntonname)!=0 && strstr(ss[i].f_mntfromname, "@")!=NULL) {
            LOG("unexcept snap mount! %s => %s\n", ss[i].f_mntfromname, ss[i].f_mntonname);
        }
        
        for(int j=0; j<i; j++) {
            if(strcmp(ss[i].f_mntfromname, ss[j].f_mntfromname)==0) {
                LOG("double mount: %s\n", ss[i].f_mntfromname);
            }
        }
    }
}

void detect_bootstraps()
{
    if(access("/var/log/apt", F_OK)==0) {
        LOG("apt log found!\n");
    }
    
    if(access("/var/log/dpkg", F_OK)==0) {
        LOG("dpkg log found!\n");
    }
    
    if(access("/var/lib/dpkg", F_OK)==0) {
        LOG("dpkg found!\n");
    }
    
    if(access("/var/lib", F_OK)==0) {
        LOG("var lib found!\n");
    }
    
    if(access("/var/lib/apt", F_OK)==0) {
        LOG("apt found!\n");
    }
    
    if(access("/var/lib/cydia", F_OK)==0) {
        LOG("cydia found!\n");
    }
    
    if(access("/var/lib/undecimus", F_OK)==0) {
        LOG("unc0ver found!\n");
    }
    
    if(access("/var/mobile/Library/Sileo", F_OK)==0) {
        LOG("Sileo found!\n");
    }
    
    if(access("/var/mobile/Library/Application Support/xyz.willy.Zebra", F_OK)==0) {
        LOG("Zebra found!\n");
    }
    
    if(access("/var/mobile/.eksafemode", F_OK)==0) {
        LOG("ellekit SafeMode!\n");
    }
    
    if(access("/private/var/mobile/.ekenablelogging", F_OK)==0) {
        LOG("ellekit Logger!\n");
    }
    
    if(access("/private/var/mobile/log.txt", F_OK)==0) {
        LOG("ellekit Logger!\n");
    }
    
}

void detect_trollStoredFilza()
{
    if(access("/var/lib/filza", F_OK)==0) {
        LOG("trollStoredFilza found!\n");
    }
    
    if(access("/var/mobile/Library/Filza", F_OK)==0) {
        LOG("trollStoredFilza found!\n");
    }
    
    if(access("/var/mobile/Library/Preferences/com.tigisoftware.Filza.plist", F_OK)==0) {
        LOG("trollStoredFilza found!\n");
    }
}

kern_return_t bootstrap_look_up(mach_port_t bp, const char* service_name, mach_port_t *sp);

static mach_port_t connect_mach_service(const char *name) {
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t kr = bootstrap_look_up(bootstrap_port, (char *)name, &port);
  return port;
}

void detect_jailbreakd()
{
    if(connect_mach_service("cy:com.saurik.substrated")) {
        LOG("checkra1n substrated found!\n");
    }
    
    if(connect_mach_service("org.coolstar.jailbreakd")) {
        LOG("coolstar jailbreakd found!\n");
    }
    
    if(connect_mach_service("jailbreakd")) {
        LOG("xina jailbreakd found!\n");
    }
}

int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
void detect_proc_flags()
{
    uint32_t flags = 0;
    csops(getpid(), 0, &flags, 0);
    //LOG("csops=%08X", flags); //22003305/lldb32003004=>3600700D, 22003305/lldb32003005
    
    if(flags & 0x00000004) {
        LOG("get-task-allow found!\n");
    }
    if(flags & 0x04000000) {
        LOG("unexcept platform binary!\n");
    }
    if(flags & 0x00000008) {
        LOG("unexcept installer!\n");
    }
    if(!(flags & 0x00000300)) {
        LOG("jit-allow found!\n");
    }
    if(flags & 0x00004000) {
        LOG("unexcept entitlements!\n");
    }
}

void detect_jb_payload()
{
    mach_port_t object_name;
    mach_vm_size_t region_size=0;
    mach_vm_address_t region_base = (uint64_t)vm_region_64;

    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT_64;

    vm_region_64(mach_task_self(), (vm_address_t*)&region_base, (vm_size_t*)&region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_cnt, &object_name);
    
    if(info.protection != VM_PROT_READ) {
        LOG("jb payload injected!\n");
    }
}

void detect_exception_port()
{
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count=0;
    
    mach_port_t task = mach_task_self();

    task_get_exception_ports(task, EXC_MASK_ALL, masks, &count, ports, behaviors, flavors);

    //LOG("got exception ports count=%d\n", count);

    for (int i = 0;i < count; i++)
    {
        //LOG("port[%d] mask=%08X port=%08X behavior=%08X flavor=%08X\n", i, masks[i], ports[i], behaviors[i], flavors[i]);
        //default: port[0] mask=00001BFE port=00000000 behavior=00000000 flavor=00000000
        //some jailbreak will set launchd exception port and subproces will auto inherit it.
        //to restore it we can task_set_exception_ports(task, 0x00001BFE, MACH_PORT_NULL, 0, 0));
        if((masks[i] & EXC_MASK_BAD_ACCESS) && ports[i]) {
            LOG("unexept exception port %08X\n", ports[i]);
        }
    }
}

void detect_jb_preboot()
{
    {
        struct statfs s={0};
        statfs("/usr/standalone/firmware", &s);
        
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/../../../procursus", s.f_mntfromname);
        if(access(path, F_OK)==0) {
            LOG("jb files in preboot!\n");
        }
    }
    
    {
        struct statfs s={0};
        statfs("/private/preboot", &s);
        if(!(s.f_flags & MNT_RDONLY)) {
            LOG("preboot writeable!\n");
        }
    }
}

void detect_jailbroken_apps()
{
    char* appids[] = {
        "com.xina.jailbreak",
        "com.opa334.Dopamine",
        "com.tigisoftware.Filza",
        "org.coolstar.SileoStore",
        "ws.hbang.Terminal",
        "xyz.willy.Zebra",
        "shshd",
    };
    
    char* paths[][3] = {
        {"","Library/Preferences",".plist"},
        {"","Library/Application Support/Containers",""},
        {"","Library/SplashBoard/Snapshots",""},
        {"","Library/Caches",""},
        {"","Library/Saved Application State",".savedState"},
        {"","Library/WebKit",""},
        {"","Library/Cookies",".binarycookies"},
        {"","Library/HTTPStorages",""},
    };
    
    for(int i=0; i<sizeof(paths)/sizeof(paths[0]); i++) {
        for(int j=0; j<sizeof(appids)/sizeof(appids[0]); j++) {
            char mobile[PATH_MAX];
            snprintf(mobile,sizeof(mobile),"/var/mobile/%s/%s%s%s", paths[i][1], appids[j], paths[i][0], paths[i][2]);
            if(access(mobile, F_OK)==0) {
                LOG("jailbroken app found %s\n", mobile);
            }
            char root[PATH_MAX];
            snprintf(root,sizeof(root),"/var/root/%s/%s%s%s", paths[i][1], appids[j], paths[i][0], paths[i][2]);
            if(access(root, F_OK)==0) {
                LOG("jailbroken app found %s\n", root);
            }
        }
    }
}

void detect_removed_varjb()
{
    /*
     Maybe you temporarily delete this symlink, but you can't guarantee that you will never make a mistake.
     
     And you never know which app will add this detection in the next update,
        unless you remove this symbolic link before opening every app, but then you will go crazy.
     */
    
    char* buf[PATH_MAX]={0};
    if(readlink("/var/jb", buf, sizeof(buf))>0) {
        //we can save the link to userDefaults/keyChains/pasteBoard, or send to server and bind it to your device-id/app-account
        [NSUserDefaults.standardUserDefaults setObject:[NSString stringWithUTF8String:buf] forKey:@"/var/jb"];
    }
    
    NSString* saved = [NSUserDefaults.standardUserDefaults stringForKey:@"/var/jb"];
    if(access(saved.UTF8String, F_OK)==0) {
        LOG("removed /var/jb found! %s\n", saved.UTF8String);
    }
}

void detect_fugu15Max()
{
    if(access("/usr/lib/systemhook.dylib", F_OK)==0) {
        LOG("systemhook.dylib found!\n");
    }
    if(access("/usr/lib/sandbox.plist", F_OK)==0) {
        LOG("sandbox.plist found!\n");
    }
    if(access("/var/log/launchdhook.log", F_OK)==0) {
        LOG("launchdhook.log found!\n");
    }
    
    struct statfs s={0};
    statfs("/usr/lib", &s);
    if(strcmp("/", s.f_mntonname)!=0) {
        LOG("fakelib found! %s\n", s.f_mntfromname);
    }
}

void detect_url_schemes()
{
    //jailbroken app's scheme doesn't need to define in Info.plist ?
    static char* schemes[] = {
        "sileo",
        "zbra",
        "cydia",
        "installer",
        "apt-repo",
        "filza",
    };
    
    for(int i=0; i<sizeof(schemes)/sizeof(schemes[0]); i++) dispatch_async(dispatch_get_main_queue(), ^{
        //only available in main runloop?
        BOOL canOpen = [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:[NSString stringWithFormat:@"%s://", schemes[i]]]];
        if(canOpen) LOG("URLScheme found: %s\n", schemes[i]);
    });
}

void detect_jbapp_plugins()
{
    NSArray* pluginIDs = @[
        @0xed9a7d2e20b489c1,
        @0xa17028497f7ef4e2,
    ];
    
    id workspace = [NSClassFromString(@"LSApplicationWorkspace") performSelector:@selector(defaultWorkspace)];

    NSArray *plugins = [workspace performSelector:@selector(installedPlugins)];
    for (id plugin in plugins)
    {
        id appBundle = [plugin performSelector:@selector(containingBundle)];
        if(appBundle) {
            NSString* appIdentifier = [appBundle performSelector:@selector(bundleIdentifier)];
//            if(![appIdentifier hasPrefix:@"com.apple."]) NSLog(@"installed app: %@", appIdentifier);
        }
        
        NSString* pluginIdentifier = [plugin performSelector:@selector(pluginIdentifier)];
        if([pluginIDs containsObject:@(pluginIdentifier.hash)]) {
            NSLog(@"detect jbapp plugin: %@ %lx", pluginIdentifier, pluginIdentifier.hash);
        }
    }
}

void detect_jailbreak_sigs()
{
#define JBSIGS(l,h,x) assert(l==sizeof(x)); uint8_t sig_##h[] = x;
#include "jbsigs.h"
    
    struct {char* tag;size_t size;void* data;} jbsigs[] = {
#define JBSIGS(l,h,x) {#h,l,sig_##h},
#include "jbsigs.h"
    };
    
    for(int i=0; i<sizeof(jbsigs)/sizeof(jbsigs[0]); i++)
    {
        char path[PATH_MAX];
        snprintf(path,sizeof(path),"%s/tmp/%lx",getenv("HOME"),arc4random());

        int fd = open(path, O_RDWR|O_CREAT, 0755);
        assert(fd >= 0);

        fsignatures_t sigreg;
        sigreg.fs_file_start = 0;
        sigreg.fs_blob_start = jbsigs[i].data;
        sigreg.fs_blob_size  = jbsigs[i].size;
        if(fcntl(fd, F_ADDSIGS, &sigreg)==0)
        {
            struct fgetsigsinfo siginfo = {0, GETSIGSINFO_PLATFORM_BINARY, 0};
            assert(fcntl(fd, F_GETSIGSINFO, &siginfo)==0);
            
            LOG("jailbreak actived! %s : %d\n", jbsigs[i].tag, siginfo.fg_sig_is_platform);
            //break;
        }
        
        close(fd);
        unlink(path);
    }
}

void detect_jailbreak_port()
{
    char* ports[] = {
        "cy:com.saurik.substrated",
        "cy:ws.hbang.common.preferencesservice",
        "lh:ws.hbang.common.preferencesservice"
    };
    for(int i=0; i<sizeof(ports)/sizeof(ports[0]); i++) {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(bootstrap_port, ports[i], &port);
        if(kr==0 || kr==1102) {
            LOG("jailbreak port %s found!\n", ports[i]);
        } else if(kr==1100) {
            LOG("jailbreak port %s not found.\n", ports[i]);
        } else {
            LOG("jailbreak port %s unknown err: %s,%s\n", ports[i], kr, mach_error_string(kr));
        }
    }
}

#include <xpc/xpc.h>
#include <xpc_private.h>

struct _os_alloc_once_s {
    long once;
    void *ptr;
};

struct xpc_global_data {
    uint64_t    a;
    uint64_t    xpc_flags;
    mach_port_t    task_bootstrap_port;  /* 0x10 */
#ifndef _64
    uint32_t    padding;
#endif
    xpc_object_t    xpc_bootstrap_pipe;   /* 0x18 */
};

extern struct _os_alloc_once_s _os_alloc_once_table[];
extern void* _os_alloc_once(struct _os_alloc_once_s *slot, size_t sz, os_function_t init);

#define JBS_DOMAIN_SYSTEMWIDE 1
#define JBS_SYSTEMWIDE_GET_JBROOT 1

void detect_launchd_jbserver()
{
    struct xpc_global_data* globalData = NULL;
    if (_os_alloc_once_table[1].once == -1) {
        globalData = _os_alloc_once_table[1].ptr;
    }
    else {
        globalData = _os_alloc_once(&_os_alloc_once_table[1], 472, NULL);
        if (!globalData) _os_alloc_once_table[1].once = -1;
    }
    if (!globalData) {
        LOG("invalid globalData!\n");
        return;
    }
    
    if (!globalData->xpc_bootstrap_pipe) {
        mach_port_t *initPorts;
        mach_msg_type_number_t initPortsCount = 0;
        if (mach_ports_lookup(mach_task_self(), &initPorts, &initPortsCount) == 0) {
            globalData->task_bootstrap_port = initPorts[0];
            globalData->xpc_bootstrap_pipe = xpc_pipe_create_from_port(globalData->task_bootstrap_port, 0);
        }
    }
    if (!globalData->xpc_bootstrap_pipe) {
        LOG("invalid xpc_bootstrap_pipe!\n");
        return;
    }
    xpc_object_t xpipe = globalData->xpc_bootstrap_pipe;

    xpc_object_t xdict = xpc_dictionary_create_empty();

    xpc_dictionary_set_uint64(xdict, "jb-domain", JBS_DOMAIN_SYSTEMWIDE);
    xpc_dictionary_set_uint64(xdict, "action", JBS_SYSTEMWIDE_GET_JBROOT);
        
    xpc_object_t xreply = NULL;

    int err = xpc_pipe_routine_with_flags(xpipe, xdict, &xreply, 0);
    LOG("xpc_pipe_routine_with_flags error=%d xreply=%p\n", err, xreply);

    if (err != 0) {
        return;
    }
    
    if(xreply) {
        const char *replyRootPath = xpc_dictionary_get_string(xreply, "root-path");
        LOG("dopamine2 installed: %s\n", replyRootPath);
    }
}

/* bypass all jb-bypass: FlyJB,Shadow,A-Bypass etc... */
@interface NSObject(JBDetect15) + (void)initialize; @end
@implementation NSObject(JBDetect15)
+ (void)initialize
{
    static int loaded=0;
    if(loaded++==0) {
        
        LOG("Don't try to patch/hook me, it's a Kids's trick!\n");
        
        // NS Foundation is not available here

        detect_rootlessJB();
        detect_kernBypass();
        detect_chroot();
        detect_mount_fs();
        detect_bootstraps();
        detect_trollStoredFilza();
        detect_jailbreakd();
        detect_proc_flags();
        detect_exception_port();
        detect_jb_payload();
        detect_jb_preboot();
        detect_jailbroken_apps();
        detect_fugu15Max();
        detect_jailbreak_sigs();
        detect_jailbreak_port();
        detect_launchd_jbserver();
        
        // wait for NS Foundation to initialize.
        dispatch_async(dispatch_get_main_queue(), ^{
            detect_removed_varjb();
            detect_url_schemes();
            detect_jbapp_plugins();
        });
    }
}
@end

#import "AppDelegate.h"
int main(int argc, char * argv[])
{
    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([AppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
