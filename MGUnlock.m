// MGUnlock.m — v2.0 门禁跳过注入库
// 运行时替换验证函数，不改主程序字节（绕过 BinaryIntegrityChecker）
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// 直接返回 YES 的 checkToken:
static BOOL MGTokenOK(id self, SEL _cmd, id token) {
    return YES;
}

// 直接返回 YES 的完整性校验
static BOOL MGIntegrityOK(id self, SEL _cmd) {
    return YES;
}

// 通用：把某个类某个方法替换成返回 YES
static void MGSwizzleBOOL(NSString *clsName, NSString *selName) {
    Class c = NSClassFromString(clsName);
    if (!c) return;
    SEL sel = NSSelectorFromString(selName);
    Method m = class_getInstanceMethod(c, sel);
    if (!m) return;
    IMP ok = (IMP)MGTokenOK;
    if ([selName containsString:@"Integrity"]) ok = (IMP)MGIntegrityOK;
    const char *types = method_getTypeEncoding(m);
    // 如果原方法返回 BOOL（types 以 'B'/'c' 开头），直接换 IMP
    if (types && (types[0] == 'B' || types[0] == 'c')) {
        class_replaceMethod(c, sel, ok, types);
        NSLog(@"[MGUnlock] swizzled %@ %@ (%s)", clsName, selName, types);
    } else {
        NSLog(@"[MGUnlock] skip %@ %@ type=%s", clsName, selName, types);
    }
}

static void MGApply(void) {
    // 授权核心
    MGSwizzleBOOL(@"_LicenseVerifier", @"checkToken:");
    MGSwizzleBOOL(@"_LicenseVerifier", @"computeSignature:");
    MGSwizzleBOOL(@"_SE_LicenseCore", @"scanTokenEx:");
    MGSwizzleBOOL(@"_RZ_AuthCore", @"auditTokenEx:");
    MGSwizzleBOOL(@"_RZ_AuthCore", @"fetchSignatureEx:");
    MGSwizzleBOOL(@"_RZ_AuthCore", @"scanReceipt");
    MGSwizzleBOOL(@"_SecureBootstrap", @"validateIntegrityStrict");
    MGSwizzleBOOL(@"_SecureBootstrap", @"computeFingerprintStrict");
    NSLog(@"[MGUnlock] applied, classes=%lu", (unsigned long)objc_getClassList(NULL, 0));
}

__attribute__((constructor))
static void MGUnlockInit(void) {
    NSLog(@"[MGUnlock] loaded");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        MGApply();
    });
}
