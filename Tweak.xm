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

static int s_didCFunctionHooks = 0;
static int s_didObjCSwizzle = 0;
static const struct mach_header *s_vcamMh = NULL;

// vcam125 globals (offsets from dylib base, found via static reverse)
//   g_isLicenseValid  byte @ 0x63ab4
//   g_features        uint32 LE @ 0x63ab8
//   g_runtime_keys    32 bytes @ 0x63abc
//   g_expiry          x64 @ 0x63980 (large value, unix-ish)
static void writeVcamIvars(const struct mach_header *mh) {
    if (!mh) return;
    uint8_t *base = (uint8_t *)mh;
    @try {
        // g_isLicenseValid = 1
        *(volatile uint8_t *)(base + 0x63ab4) = 1;
        // g_features = 0xFFFFFFFF
        *(volatile uint32_t *)(base + 0x63ab8) = 0xFFFFFFFFU;
        // g_runtime_keys = 32 bytes of 0x42 (consistent pattern, not 0/random)
        for (int i = 0; i < 32; i++) {
            ((volatile uint8_t *)(base + 0x63abc))[i] = 0x42;
        }
        // g_expiry (uint64 LE) = 2099 unix
        *(volatile uint64_t *)(base + 0x63980) = 4070908800ULL;
    } @catch (NSException *e) {
        NSLog(@"[v17bypass] writeVcamIvars exception: %@", e);
    }
}

// Periodically re-write ivars to enforce in case vcam125 internal code clears them
static void startIvarEnforcer(void) {
    static int s_started = 0;
    if (s_started) return;
    s_started = 1;
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(timer,
                              dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC),
                              100 * NSEC_PER_MSEC,  // every 100ms
                              10 * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(timer, ^{
        if (s_vcamMh) writeVcamIvars(s_vcamMh);
    });
    dispatch_resume(timer);
    NSLog(@"[v17bypass] ivar enforcer timer started (100ms interval)");
}

// Apply C-function hooks (gate2 + SecKey) — these only need vcam125 dylib loaded
static void applyCHooks(const struct mach_header *mh) {
    if (s_didCFunctionHooks) return;
    s_didCFunctionHooks = 1;

    // gate2 (vcam125 dylib base + 0xe9f4)
    void *gate2_addr = (void *)((uintptr_t)mh + 0xe9f4);
    @try {
        MSHookFunction(gate2_addr, (void *)my_gate2, (void **)&orig_gate2);
        NSLog(@"[v16bypass] gate2 @ %p hooked", gate2_addr);
    } @catch (NSException *e) {
        NSLog(@"[v16bypass] gate2 hook FAILED: %@", e);
    }

    // SecKeyVerifySignature framework hook
    void *sec_ptr = dlsym(RTLD_DEFAULT, "SecKeyVerifySignature");
    if (sec_ptr && !orig_SecKeyVerifySig) {
        @try {
            MSHookFunction(sec_ptr, (void *)my_SecKeyVerifySig, (void **)&orig_SecKeyVerifySig);
            NSLog(@"[v16bypass] SecKeyVerifySignature hooked");
        } @catch (NSException *e) {
            NSLog(@"[v16bypass] SecKeyVerifySig hook FAILED: %@", e);
        }
    }
}

// Try ObjC class swizzle — called repeatedly until classes appear
static void tryObjCSwizzle(int retriesLeft) {
    if (s_didObjCSwizzle) return;
    Class lc = objc_getClass("LicenseCore");
    Class vc = objc_getClass("VCamCore");
    if (!lc || !vc) {
        if (retriesLeft <= 0) {
            NSLog(@"[v16bypass] gave up swizzle: lc=%@ vc=%@ (classes never appeared after 100 retries)",
                  lc, vc);
            return;
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC),
                       dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0),
                       ^{ tryObjCSwizzle(retriesLeft - 1); });
        return;
    }

    s_didObjCSwizzle = 1;
    NSLog(@"[v16bypass] *** classes appeared after retry, swizzling now");

    swizzle_class(lc, @selector(isLicenseValid),       (IMP)r_isLicenseValid,       "isLicenseValid");
    swizzle_class(lc, @selector(loadPersistedLicense), (IMP)r_loadPersistedLicense, "loadPersistedLicense");
    swizzle_class(lc, @selector(licenseStatusString),  (IMP)r_licenseStatusString,  "licenseStatusString");
    swizzle_class(lc, @selector(features),             (IMP)r_features,             "features");
    swizzle_class(lc, @selector(expiryUnix),           (IMP)r_expiryUnix,           "expiryUnix");
    swizzle_inst(vc, @selector(isEnabled),             (IMP)r_VC_isEnabled,            "VC.isEnabled");
    // v18: REMOVED hasReplacementFrame swizzle.
    // v17 Camera 黑屏: hasReplFrame=YES 让 emit hook 进 renderReplacement,
    // 但 LVP 没真帧 → 内部 deref nil → SIGSEGV → msd cycle.
    // 让它返实际值: 没 fake video 时 NO → emit hook 走原图 path 不 crash.
    // 用户在 vcam125 UI 选视频后 LVP 自然有帧, hasReplFrame 真实返 YES.
    // swizzle_inst(vc, @selector(hasReplacementFrame), (IMP)r_VC_hasReplacementFrame, "VC.hasReplacementFrame");
    NSLog(@"[v16bypass] *** ObjC swizzle complete");
}

static void onImageLoad(const struct mach_header *mh, intptr_t slide) {
    Dl_info info;
    if (dladdr((const void *)mh, &info) == 0) return;
    if (!info.dli_fname) return;
    if (!strstr(info.dli_fname, "vcameracrack")) return;

    NSLog(@"[v17bypass] *** vcameracrack loaded at %p slide=0x%lx path=%s",
          mh, (unsigned long)slide, info.dli_fname);
    s_vcamMh = mh;

    // C-function hooks immediately
    applyCHooks(mh);

    // Write ivars NOW (before vcam125 +load tries to verify license)
    writeVcamIvars(mh);

    // Start periodic re-write timer to enforce against vcam125's own clearing
    startIvarEnforcer();

    // ObjC class hooks deferred via retry
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        tryObjCSwizzle(100);
    });
}

// ============== ctor — register dyld callback ==============

__attribute__((constructor))
static void v16_init(void) {
    NSString *proc = [[NSProcessInfo processInfo] processName];
    NSLog(@"[v16bypass] ctor in process: %@", proc);
    _dyld_register_func_for_add_image(onImageLoad);
    NSLog(@"[v16bypass] dyld add_image callback registered");

    // ALSO start an independent retry loop in case dyld callback never sees vcameracrack
    // (already-loaded edge case — though dyld should fire for already-loaded images)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 200 * NSEC_PER_MSEC),
                   dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0),
                   ^{ tryObjCSwizzle(100); });
}
