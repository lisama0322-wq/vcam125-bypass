// vcam125 bypass tweak — runtime hook (NO __text disk modification)
//
// 装在 mediaserverd + SpringBoard 跟 vcameracrack.dylib 共存. 用 dyld add_image
// callback 监听 vcameracrack 加载时刻, 立即 swap ObjC method IMP + MSHookFunction
// internal C function (gate2) + framework SecKeyVerifySignature.
//
// vcam125 dylib 在磁盘上一个字节没动 → 没 PAC/codesign/RootHide 装载层风险.
// 之前 v6-v14 全因 patch dylib 字节让 SB 卡 boot, v15 走完全不同的路.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <substrate.h>
#import <Security/Security.h>

// ============== Replacement IMPs ==============

static BOOL r_isLicenseValid(id self, SEL _cmd) { return YES; }
static BOOL r_loadPersistedLicense(id self, SEL _cmd) { return YES; }
static NSString *r_licenseStatusString(id self, SEL _cmd) {
    return @"已授权 (v15 bypass)";
}
static unsigned int r_features(id self, SEL _cmd) { return 0xFFFFFFFFU; }
static long long r_expiryUnix(id self, SEL _cmd) { return 4070908800LL; }  // 2099

static BOOL r_VC_isEnabled(id self, SEL _cmd) { return YES; }
static BOOL r_VC_hasReplacementFrame(id self, SEL _cmd) { return YES; }

// ============== gate2 hook (vcam125 internal C function @ 0xe9f4) ==============

typedef int (*gate2_fn_t)(void);
static gate2_fn_t orig_gate2 = NULL;
static int my_gate2(void) { return 1; }

// ============== SecKeyVerifySignature hook (Apple framework) ==============

typedef Boolean (*SecKeyVerifySig_fn_t)(SecKeyRef, CFStringRef, CFDataRef, CFDataRef, CFErrorRef *);
static SecKeyVerifySig_fn_t orig_SecKeyVerifySig = NULL;
static Boolean my_SecKeyVerifySig(SecKeyRef key, CFStringRef alg, CFDataRef signed_data, CFDataRef sig, CFErrorRef *err) {
    if (err) *err = NULL;
    return true;
}

// ============== Helpers ==============

static void swizzle_class(Class cls, SEL sel, IMP newImp, const char *label) {
    if (!cls) return;
    Method m = class_getClassMethod(cls, sel);
    if (m) {
        method_setImplementation(m, newImp);
        NSLog(@"[v15bypass] swap +[%s %s]", class_getName(cls), sel_getName(sel));
    } else {
        NSLog(@"[v15bypass] +[%s %s] not found", class_getName(cls), sel_getName(sel));
    }
}
static void swizzle_inst(Class cls, SEL sel, IMP newImp, const char *label) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (m) {
        method_setImplementation(m, newImp);
        NSLog(@"[v15bypass] swap -[%s %s]", class_getName(cls), sel_getName(sel));
    } else {
        NSLog(@"[v15bypass] -[%s %s] not found", class_getName(cls), sel_getName(sel));
    }
}

// ============== dyld add_image callback ==============

static int s_didApply = 0;

static void onImageLoad(const struct mach_header *mh, intptr_t slide) {
    if (s_didApply) return;
    Dl_info info;
    if (dladdr((const void *)mh, &info) == 0) return;
    if (!info.dli_fname) return;
    const char *path = info.dli_fname;
    if (!strstr(path, "vcameracrack")) return;
    s_didApply = 1;

    NSLog(@"[v15bypass] *** vcameracrack loaded at %p (slide 0x%lx) path=%s", mh, (unsigned long)slide, path);

    // 1. ObjC method swizzles
    Class lc = objc_getClass("LicenseCore");
    if (lc) {
        swizzle_class(lc, @selector(isLicenseValid),       (IMP)r_isLicenseValid,       "isLicenseValid");
        swizzle_class(lc, @selector(loadPersistedLicense), (IMP)r_loadPersistedLicense, "loadPersistedLicense");
        swizzle_class(lc, @selector(licenseStatusString),  (IMP)r_licenseStatusString,  "licenseStatusString");
        swizzle_class(lc, @selector(features),             (IMP)r_features,             "features");
        swizzle_class(lc, @selector(expiryUnix),           (IMP)r_expiryUnix,           "expiryUnix");
    } else {
        NSLog(@"[v15bypass] !!! LicenseCore class not found");
    }
    Class vc = objc_getClass("VCamCore");
    if (vc) {
        swizzle_inst(vc, @selector(isEnabled),            (IMP)r_VC_isEnabled,            "VC.isEnabled");
        swizzle_inst(vc, @selector(hasReplacementFrame),  (IMP)r_VC_hasReplacementFrame,  "VC.hasReplacementFrame");
    } else {
        NSLog(@"[v15bypass] !!! VCamCore class not found");
    }

    // 2. MSHookFunction on internal gate2 (vcam125 dylib base + 0xe9f4)
    void *gate2_addr = (void *)((uintptr_t)mh + 0xe9f4);
    @try {
        MSHookFunction(gate2_addr, (void *)my_gate2, (void **)&orig_gate2);
        NSLog(@"[v15bypass] gate2 @ %p hooked (orig=%p)", gate2_addr, orig_gate2);
    } @catch (NSException *e) {
        NSLog(@"[v15bypass] gate2 hook FAILED: %@", e);
    }

    // 3. SecKeyVerifySignature framework hook (intercepts vcam125's verify call)
    void *sec_ptr = dlsym(RTLD_DEFAULT, "SecKeyVerifySignature");
    if (sec_ptr && !orig_SecKeyVerifySig) {
        @try {
            MSHookFunction(sec_ptr, (void *)my_SecKeyVerifySig, (void **)&orig_SecKeyVerifySig);
            NSLog(@"[v15bypass] SecKeyVerifySignature @ %p hooked", sec_ptr);
        } @catch (NSException *e) {
            NSLog(@"[v15bypass] SecKeyVerifySig hook FAILED: %@", e);
        }
    }

    NSLog(@"[v15bypass] *** all hooks applied");
}

// ============== ctor — register dyld callback ==============

__attribute__((constructor))
static void v15_init(void) {
    NSString *proc = [[NSProcessInfo processInfo] processName];
    NSLog(@"[v15bypass] ctor in process: %@", proc);
    _dyld_register_func_for_add_image(onImageLoad);
    NSLog(@"[v15bypass] dyld add_image callback registered");
}
