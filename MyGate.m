//
//  MyGate.m  —  替换 CCCoreLicense.dylib 的自有授权模块
//  编译产物重命名为 CCCoreLicense.dylib，install_name 保持
//  @executable_path/CCCoreLicense.dylib，主程序无需改动。
//
//  加载顺序：CoreOffline.work.dylib 先 → 本模块后
//  因此本模块的 hook 位于 CoreOffline 之上，可保存其 imp 形成链。
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <Security/Security.h>
#import <CFNetwork/CFNetwork.h>
#import <CommonCrypto/CommonHMAC.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <string.h>
#import <stdlib.h>
#import <math.h>

// MGHome.m 提供的首页挂载函数
extern void MGShowHome(void);

// ============================ 配置 ============================
// 用 IP 直连：kAPIHost 填公网 IP，kUseTLS = NO
// 以后换成域名 + 证书：改 host、端口 443、kUseTLS = YES
static NSString *const kAPIHost      = @"101.251.162.85";
static const  UInt16    kAPIPort     = 8443;
static NSString *const kAPIPrefix    = @"/api/v1";
static const  BOOL      kUseTLS      = NO;      // 走 CFStream 裸 socket，不受 ATS 限制

static NSString *const kAppKey       = @"core-ios";
static NSString *const kAppSecret    = @"8731cfa45a76a32bade5ad3a3b72fa92dc1d0a590ecead2c159bdb3ded15ca4e";
static NSString *const kProduct      = @"core";
static NSString *const kDisplayName  = @"JUANMAO";          // 首页/门禁显示名
static NSString *const kBannerFile   = @"mg_banner.png";     // 打包进 .app 的横幅图
static const  int       kOfflineDays  = 3;                   // 离线宽限天数
static const  int       kHeartbeatMin = 30;                   // 心跳间隔（分钟）

// ============================ 日志 ============================
#define MGLog(fmt, ...) NSLog(@"[MyGate] " fmt, ##__VA_ARGS__)

// ============================ Keychain ============================
static NSMutableDictionary *MGKeychainQuery(NSString *account) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass]       = (__bridge id)kSecClassGenericPassword;
    q[(__bridge id)kSecAttrService] = @"com.mygate.license";
    q[(__bridge id)kSecAttrAccount] = account;
    return q;
}

static NSString *MGKeychainGet(NSString *account) {
    NSMutableDictionary *q = MGKeychainQuery(account);
    q[(__bridge id)kSecReturnData] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    CFTypeRef out = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &out) == errSecSuccess && out) {
        NSData *d = (__bridge_transfer NSData *)out;
        return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    }
    return nil;
}

static void MGKeychainSet(NSString *account, NSString *value) {
    if (!value) {
        SecItemDelete((__bridge CFDictionaryRef)MGKeychainQuery(account));
        return;
    }
    NSData *d = [value dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *q = MGKeychainQuery(account);
    SecItemDelete((__bridge CFDictionaryRef)q);
    q[(__bridge id)kSecValueData] = d;
    q[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    SecItemAdd((__bridge CFDictionaryRef)q, NULL);
}

// ============================ 设备指纹 ============================
static NSString *MGMachine(void) {
    struct utsname u; uname(&u);
    return [NSString stringWithUTF8String:u.machine];
}

static NSString *MGDeviceID(void) {
    // 安装级稳定 ID：Keychain 里生成一次，卸载重装仍保留
    static NSString *cached = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        cached = MGKeychainGet(@"device_uuid");
        if (!cached) {
            cached = [[NSUUID UUID] UUIDString].lowercaseString;
            MGKeychainSet(@"device_uuid", cached);
        }
    });
    return cached;
}

static NSString *MGFingerprint(void) {
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"";
    NSString *raw = [NSString stringWithFormat:@"%@|%@|%@|%@",
                     MGDeviceID(), idfv, MGMachine(),
                     [[NSBundle mainBundle] bundleIdentifier] ?: @""];
    NSData *d = [raw dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char h[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(d.bytes, (CC_LONG)d.length, h);
    NSMutableString *s = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [s appendFormat:@"%02x", h[i]];
    return s;
}

// ============================ 签名 ============================
static NSString *MGHMAC(NSString *msg) {
    NSData *k = [kAppSecret dataUsingEncoding:NSUTF8StringEncoding];
    NSData *m = [msg dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char h[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, k.bytes, k.length, m.bytes, m.length, h);
    NSMutableString *s = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [s appendFormat:@"%02x", h[i]];
    return s;
}

// ============================ 本地存储 ============================
@interface MGLicense : NSObject
@property (nonatomic, copy) NSString *token;
@property (nonatomic, copy) NSString *cardMask;
@property (nonatomic, assign) NSTimeInterval expireAt;
@property (nonatomic, assign) NSTimeInterval lastSeen;   // 服务器时间
@property (nonatomic, assign) NSTimeInterval lastVerified;
@property (nonatomic, copy) NSString *lastError;
+ (instancetype)shared;
- (void)load;
- (void)save;
- (BOOL)locallyValid;
- (void)clear;
@end

@implementation MGLicense
+ (instancetype)shared {
    static MGLicense *s; static dispatch_once_t o;
    dispatch_once(&o, ^{ s = [MGLicense new]; [s load]; });
    return s;
}
- (void)load {
    self.token        = MGKeychainGet(@"token");
    self.cardMask     = MGKeychainGet(@"card_mask");
    self.expireAt     = [[NSUserDefaults standardUserDefaults] doubleForKey:@"mg_expire"];
    self.lastSeen     = [[NSUserDefaults standardUserDefaults] doubleForKey:@"mg_last_seen"];
    self.lastVerified = [[NSUserDefaults standardUserDefaults] doubleForKey:@"mg_last_verified"];
}
- (void)save {
    MGKeychainSet(@"token", self.token);
    MGKeychainSet(@"card_mask", self.cardMask);
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setDouble:self.expireAt forKey:@"mg_expire"];
    [d setDouble:self.lastSeen forKey:@"mg_last_seen"];
    [d setDouble:self.lastVerified forKey:@"mg_last_verified"];
    [d synchronize];
}
- (void)clear {
    self.token = nil; self.cardMask = nil; self.expireAt = 0;
    self.lastSeen = 0; self.lastVerified = 0;
    [self save];
}
- (BOOL)locallyValid {
    if (self.token.length == 0 || self.expireAt <= 0) return NO;
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now >= self.expireAt) return NO;
    // 时间回拨检测：本地时间明显早于上次服务器时间 → 视为异常
    if (self.lastSeen > 0 && now + 300 < self.lastSeen) return NO;
    // 离线宽限
    if (self.lastVerified > 0 &&
        now - self.lastVerified > kOfflineDays * 86400.0) return NO;
    return YES;
}
@end

// ============================ HTTP（CFStream 裸 socket） ============================
// 不走 NSURLSession：既绕开 iOS ATS 的明文限制，也绕开 CoreOffline 的
// NSURLSessionTask hook。IP 直连时用这套；以后换域名 + TLS 只改 kUseTLS。
static NSData *MGDechunk(NSData *in) {
    NSMutableData *out = [NSMutableData data];
    const uint8_t *p = in.bytes, *end = p + in.length;
    while (p < end) {
        const uint8_t *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol) break;
        long len = strtol((const char *)p, NULL, 16);
        if (len <= 0) break;
        p = eol + 1;
        if (p + len > end) break;
        [out appendBytes:p length:(NSUInteger)len];
        p += len;
        while (p < end && (*p == '\r' || *p == '\n')) p++;
    }
    return out;
}

static NSDictionary *MGRawPostSync(NSString *path, NSDictionary *body, NSError **err) {
    NSMutableDictionary *payload = [body mutableCopy] ?: [NSMutableDictionary dictionary];
    payload[@"app"] = kAppKey;
    payload[@"ts"]  = @((long long)[[NSDate date] timeIntervalSince1970]);
    payload[@"dev"] = MGFingerprint();

    NSData *jd = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
    if (!jd) {
        if (err) *err = [NSError errorWithDomain:@"MyGate" code:-1
                                        userInfo:@{NSLocalizedDescriptionKey: @"请求序列化失败"}];
        return nil;
    }
    NSString *json = [[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding];
    NSString *sig  = MGHMAC(json);

    CFReadStreamRef  rd = NULL;
    CFWriteStreamRef wr = NULL;
    CFStreamCreatePairWithSocketToHost(kCFAllocatorDefault,
                                       (__bridge CFStringRef)kAPIHost,
                                       (UInt32)kAPIPort, &rd, &wr);
    if (!rd || !wr) {
        if (err) *err = [NSError errorWithDomain:@"MyGate" code:-2
                                        userInfo:@{NSLocalizedDescriptionKey: @"连接失败"}];
        return nil;
    }

    if (kUseTLS) {
        NSDictionary *ssl = @{
            (__bridge id)kCFStreamSSLLevel:
                (__bridge id)kCFStreamSocketSecurityLevelNegotiatedSSL,
            (__bridge id)kCFStreamSSLPeerName: kAPIHost,
        };
        CFReadStreamSetProperty(rd, kCFStreamPropertySSLSettings,
                                (__bridge CFDictionaryRef)ssl);
        CFWriteStreamSetProperty(wr, kCFStreamPropertySSLSettings,
                                 (__bridge CFDictionaryRef)ssl);
    }
    CFReadStreamSetProperty(rd, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue);
    CFWriteStreamSetProperty(wr, kCFStreamPropertyShouldCloseNativeSocket, kCFBooleanTrue);

    if (!CFReadStreamOpen(rd) || !CFWriteStreamOpen(wr)) {
        CFRelease(rd); CFRelease(wr);
        if (err) *err = [NSError errorWithDomain:@"MyGate" code:-3
                                        userInfo:@{NSLocalizedDescriptionKey: @"网络不可用"}];
        return nil;
    }

    // socket 超时，避免卡死
    CFDataRef fdData = CFReadStreamCopyProperty(rd, kCFStreamPropertySocketNativeHandle);
    if (fdData) {
        int fd = -1;
        CFDataGetBytes(fdData, CFRangeMake(0, sizeof(int)), (UInt8 *)&fd);
        struct timeval tv = {15, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        CFRelease(fdData);
    }

    NSMutableData *req = [NSMutableData data];
    NSString *head = [NSString stringWithFormat:
        @"POST %@%@ HTTP/1.1\r\nHost: %@\r\nX-App: %@\r\nX-Sign: %@\r\n"
        @"Content-Type: application/json\r\nContent-Length: %lu\r\n"
        @"Connection: close\r\n\r\n",
        kAPIPrefix, path, kAPIHost, kAppKey, sig, (unsigned long)jd.length];
    [req appendData:[head dataUsingEncoding:NSUTF8StringEncoding]];
    [req appendData:jd];

    const uint8_t *wp = req.bytes;
    CFIndex left = (CFIndex)req.length;
    while (left > 0) {
        CFIndex n = CFWriteStreamWrite(wr, wp, left);
        if (n <= 0) break;
        wp += n; left -= n;
    }

    NSMutableData *resp = [NSMutableData data];
    uint8_t buf[4096];
    while (1) {
        CFIndex n = CFReadStreamRead(rd, buf, sizeof(buf));
        if (n <= 0) break;
        [resp appendBytes:buf length:(NSUInteger)n];
    }
    CFReadStreamClose(rd); CFWriteStreamClose(wr);
    CFRelease(rd); CFRelease(wr);

    if (resp.length == 0) {
        if (err) *err = [NSError errorWithDomain:@"MyGate" code:-4
                                        userInfo:@{NSLocalizedDescriptionKey: @"服务器无响应"}];
        return nil;
    }

    NSData *sepData = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
    NSRange sep = [resp rangeOfData:sepData options:0
                              range:NSMakeRange(0, resp.length)];
    if (sep.location == NSNotFound) {
        if (err) *err = [NSError errorWithDomain:@"MyGate" code:-5
                                        userInfo:@{NSLocalizedDescriptionKey: @"响应格式错误"}];
        return nil;
    }
    NSString *header = [[NSString alloc] initWithData:[resp subdataWithRange:
                        NSMakeRange(0, sep.location)] encoding:NSUTF8StringEncoding];
    NSData *bodyData = [resp subdataWithRange:
                        NSMakeRange(NSMaxRange(sep), resp.length - NSMaxRange(sep))];

    NSInteger code = 0;
    if (header.length > 9) {
        NSArray *parts = [[header componentsSeparatedByString:@"\r\n"].firstObject
                          componentsSeparatedByString:@" "];
        if (parts.count >= 2) code = [parts[1] integerValue];
    }
    if ([header.lowercaseString containsString:@"transfer-encoding: chunked"]) {
        bodyData = MGDechunk(bodyData);
    }

    NSDictionary *obj = bodyData.length
        ? [NSJSONSerialization JSONObjectWithData:bodyData options:0 error:nil] : nil;

    if (code != 200 || ![obj isKindOfClass:[NSDictionary class]]) {
        if (err) *err = [NSError errorWithDomain:@"MyGate" code:code userInfo:
                         @{NSLocalizedDescriptionKey: obj[@"msg"] ?: @"服务异常"}];
        return nil;
    }
    return obj;
}

static void MGPost(NSString *path, NSDictionary *body,
                   void (^done)(NSDictionary *json, NSError *err)) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSError *e = nil;
        NSDictionary *j = MGRawPostSync(path, body, &e);
        dispatch_async(dispatch_get_main_queue(), ^{
            done(j, e);
        });
    });
}

// ============================ 授权流程 ============================
@interface MGGate : NSObject
@property (nonatomic, assign) BOOL working;
@property (nonatomic, copy) NSString *message;   // 门禁页提示
@end

@implementation MGGate
+ (instancetype)shared {
    static MGGate *s; static dispatch_once_t o;
    dispatch_once(&o, ^{ s = [MGGate new]; });
    return s;
}

- (void)activate:(NSString *)card completion:(void (^)(BOOL ok, NSString *msg))cb {
    if (self.working) { cb(NO, @"正在验证，请稍候"); return; }
    self.working = YES;
    MGPost(@"/activate", @{@"card": card ?: @"", @"product": kProduct}, ^(NSDictionary *j, NSError *e) {
        self.working = NO;
        if (!j) { cb(NO, e.localizedDescription ?: @"网络异常"); return; }
        MGLicense *lic = [MGLicense shared];
        lic.token    = j[@"token"] ?: @"";
        lic.cardMask = j[@"card_mask"] ?: @"";
        lic.expireAt = [j[@"expire_at"] doubleValue];
        lic.lastSeen = [j[@"server_time"] doubleValue];
        lic.lastVerified = [[NSDate date] timeIntervalSince1970];
        [lic save];
        if (lic.token.length == 0 || lic.expireAt <= 0) { cb(NO, @"响应无效"); return; }
        cb(YES, [NSString stringWithFormat:@"授权至 %@", [self dateText:lic.expireAt]]);
    });
}

- (void)heartbeat:(void (^)(BOOL ok))cb {
    MGLicense *lic = [MGLicense shared];
    if (lic.token.length == 0) { cb(NO); return; }
    MGPost(@"/heartbeat", @{@"token": lic.token, @"product": kProduct}, ^(NSDictionary *j, NSError *e) {
        if (!j) { cb(NO); return; }
        if ([j[@"ok"] boolValue]) {
            lic.expireAt = [j[@"expire_at"] doubleValue];
            lic.lastSeen = [j[@"server_time"] doubleValue];
            lic.lastVerified = [[NSDate date] timeIntervalSince1970];
            [lic save];
            cb(YES);
        } else {
            lic.lastError = j[@"msg"];
            [lic clear];
            cb(NO);
        }
    });
}

- (NSString *)dateText:(NSTimeInterval)t {
    NSDateFormatter *f = [NSDateFormatter new];
    f.dateFormat = @"yyyy-MM-dd HH:mm";
    return [f stringFromDate:[NSDate dateWithTimeIntervalSince1970:t]];
}
@end

// ============================ 门禁 UI ============================
@interface MGGateVC : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UILabel *hint;
@property (nonatomic, strong) UILabel *expiry;
@property (nonatomic, strong) UIButton *submit;
@property (nonatomic, copy) void (^onPass)(void);
@end

@implementation MGGateVC

- (void)viewDidLoad {
    [super viewDidLoad];
    @try {
    self.view.backgroundColor = [UIColor colorWithRed:0.05 green:0.06 blue:0.09 alpha:1];

    UILabel *title = [UILabel new];
    title.text = kDisplayName;
    title.font = [UIFont boldSystemFontOfSize:26];
    title.textColor = UIColor.whiteColor;
    title.textAlignment = NSTextAlignmentCenter;
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:title];

    UILabel *sub = [UILabel new];
    sub.text = @"请输入授权卡密";
    sub.font = [UIFont systemFontOfSize:14];
    sub.textColor = [UIColor colorWithWhite:1 alpha:0.55];
    sub.textAlignment = NSTextAlignmentCenter;
    sub.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:sub];

    self.field = [UITextField new];
    self.field.placeholder = @"XXXX-XXXX-XXXX-XXXX";
    self.field.textColor = UIColor.whiteColor;
    self.field.backgroundColor = [UIColor colorWithWhite:1 alpha:0.08];
    self.field.layer.cornerRadius = 10;
    self.field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    self.field.autocorrectionType = UITextAutocorrectionTypeNo;
    self.field.clearButtonMode = UITextFieldViewModeWhileEditing;
    self.field.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 14, 1)];
    self.field.leftViewMode = UITextFieldViewModeAlways;
    self.field.delegate = self;
    self.field.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.field];

    self.submit = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.submit setTitle:@"立即激活" forState:UIControlStateNormal];
    [self.submit setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    self.submit.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    self.submit.backgroundColor = [UIColor colorWithRed:0.20 green:0.50 blue:1.0 alpha:1];
    self.submit.layer.cornerRadius = 10;
    [self.submit addTarget:self action:@selector(tapSubmit) forControlEvents:UIControlEventTouchUpInside];
    self.submit.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.submit];

    self.hint = [UILabel new];
    self.hint.font = [UIFont systemFontOfSize:13];
    self.hint.textColor = [UIColor colorWithRed:1 green:0.45 blue:0.45 alpha:1];
    self.hint.textAlignment = NSTextAlignmentCenter;
    self.hint.numberOfLines = 0;
    self.hint.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.hint];

    self.expiry = [UILabel new];
    self.expiry.font = [UIFont systemFontOfSize:12];
    self.expiry.textColor = [UIColor colorWithWhite:1 alpha:0.35];
    self.expiry.textAlignment = NSTextAlignmentCenter;
    self.expiry.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.expiry];

    UIButton *paste = [UIButton buttonWithType:UIButtonTypeSystem];
    [paste setTitle:@"粘贴卡密" forState:UIControlStateNormal];
    [paste setTitleColor:[UIColor colorWithWhite:1 alpha:0.6] forState:UIControlStateNormal];
    paste.titleLabel.font = [UIFont systemFontOfSize:13];
    [paste addTarget:self action:@selector(tapPaste) forControlEvents:UIControlEventTouchUpInside];
    paste.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:paste];

    [NSLayoutConstraint activateConstraints:@[
        [title.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [title.bottomAnchor constraintEqualToAnchor:sub.topAnchor constant:-10],
        [sub.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [sub.bottomAnchor constraintEqualToAnchor:self.field.topAnchor constant:-28],
        [self.field.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:32],
        [self.field.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-32],
        [self.field.heightAnchor constraintEqualToConstant:50],
        [self.field.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:-20],
        [self.submit.leadingAnchor constraintEqualToAnchor:self.field.leadingAnchor],
        [self.submit.trailingAnchor constraintEqualToAnchor:self.field.trailingAnchor],
        [self.submit.topAnchor constraintEqualToAnchor:self.field.bottomAnchor constant:14],
        [self.submit.heightAnchor constraintEqualToConstant:50],
        [self.hint.leadingAnchor constraintEqualToAnchor:self.field.leadingAnchor],
        [self.hint.trailingAnchor constraintEqualToAnchor:self.field.trailingAnchor],
        [self.hint.topAnchor constraintEqualToAnchor:self.submit.bottomAnchor constant:14],
        [paste.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [paste.topAnchor constraintEqualToAnchor:self.submit.bottomAnchor constant:44],
        [self.expiry.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.expiry.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-24],
    ]];
    } @catch (NSException *e) {
        NSLog(@"[MyGate] gate ui failed: %@", e);
    }
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self.field becomeFirstResponder];
    MGLicense *l = [MGLicense shared];
    if (l.expireAt > 0) {
        self.expiry.text = [NSString stringWithFormat:@"本机记录：授权至 %@",
                            [[MGGate shared] dateText:l.expireAt]];
    }
}

- (void)tapPaste {
    NSString *s = [UIPasteboard generalPasteboard].string;
    s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (s.length) { self.field.text = s; self.hint.text = @"已粘贴"; }
    else { self.hint.text = @"剪贴板为空"; }
}

- (void)tapSubmit {
    [self.field resignFirstResponder];
    NSString *card = [self.field.text stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]].uppercaseString;
    if (card.length < 8) { self.hint.text = @"卡密格式不正确"; return; }
    self.hint.text = @"正在联网验证…";
    self.submit.enabled = NO;
    __weak typeof(self) wself = self;
    [[MGGate shared] activate:card completion:^(BOOL ok, NSString *msg) {
        __strong typeof(wself) self = wself;
        self.submit.enabled = YES;
        if (!ok) { self.hint.text = msg ?: @"激活失败"; return; }
        self.hint.textColor = [UIColor colorWithRed:0.35 green:0.9 blue:0.55 alpha:1];
        self.hint.text = msg;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if (self.onPass) self.onPass();
        });
    }];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [self tapSubmit];
    return YES;
}
@end

// ============================ 启动页 ============================
static UIWindow *gLaunchWindow = nil;
static UIWindowScene *MGFindScene(void);

static CAShapeLayer *MGArc(CGFloat radius, CGFloat start, CGFloat end,
                           UIColor *color, CGFloat width) {
    CAShapeLayer *l = [CAShapeLayer layer];
    UIBezierPath *p = [UIBezierPath bezierPathWithArcCenter:CGPointMake(0, 0)
                                                     radius:radius
                                                 startAngle:start
                                                   endAngle:end
                                                  clockwise:YES];
    l.path = p.CGPath;
    l.strokeColor = color.CGColor;
    l.fillColor = UIColor.clearColor.CGColor;
    l.lineWidth = width;
    l.lineCap = kCALineCapRound;
    return l;
}

static void MGShowLaunch(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            if (gLaunchWindow) return;
            UIWindowScene *scene = MGFindScene();
            if (!scene) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ MGShowLaunch(); });
                return;
            }

            UIViewController *vc = [UIViewController new];
            vc.view.backgroundColor = [UIColor colorWithRed:0.980 green:0.980 blue:0.984 alpha:1];
            vc.view.tag = 0x4D47;

            UIView *logoWrap = [UIView new];
            logoWrap.translatesAutoresizingMaskIntoConstraints = NO;
            [vc.view addSubview:logoWrap];

            CALayer *ring = [CALayer layer];
            ring.frame = CGRectMake(0, 0, 130, 130);
            [logoWrap.layer addSublayer:ring];

            CAShapeLayer *a1 = MGArc(59, -M_PI_2, M_PI_2,
                                     [UIColor colorWithRed:1.0 green:0.176 blue:0.42 alpha:1], 10);
            a1.position = CGPointMake(65, 65);
            [ring addSublayer:a1];

            CAShapeLayer *a2 = MGArc(59, M_PI_2, 1.5 * M_PI,
                                     [UIColor colorWithRed:0.133 green:0.851 blue:0.941 alpha:1], 10);
            a2.position = CGPointMake(65, 65);
            [ring addSublayer:a2];

            UIView *dot = [UIView new];
            dot.backgroundColor = [UIColor colorWithRed:0.047 green:0.051 blue:0.071 alpha:1];
            dot.layer.cornerRadius = 8;
            dot.translatesAutoresizingMaskIntoConstraints = NO;
            [logoWrap addSubview:dot];

            UILabel *brand = [UILabel new];
            brand.text = kDisplayName;
            brand.font = [UIFont boldSystemFontOfSize:44];
            brand.textColor = [UIColor colorWithRed:0.063 green:0.063 blue:0.078 alpha:1];
            brand.translatesAutoresizingMaskIntoConstraints = NO;
            [vc.view addSubview:brand];

            UILabel *sub = [UILabel new];
            sub.text = @"正在加载核心组件";
            sub.font = [UIFont systemFontOfSize:14];
            sub.textColor = [UIColor colorWithRed:0.549 green:0.569 blue:0.612 alpha:1];
            sub.translatesAutoresizingMaskIntoConstraints = NO;
            [vc.view addSubview:sub];

            UIView *barBg = [UIView new];
            barBg.backgroundColor = [UIColor colorWithRed:0.910 green:0.914 blue:0.933 alpha:1];
            barBg.layer.cornerRadius = 3.5;
            barBg.translatesAutoresizingMaskIntoConstraints = NO;
            [vc.view addSubview:barBg];

            UIView *barFg = [UIView new];
            barFg.backgroundColor = [UIColor colorWithRed:1.0 green:0.176 blue:0.42 alpha:1];
            barFg.layer.cornerRadius = 3.5;
            barFg.translatesAutoresizingMaskIntoConstraints = NO;
            [barBg addSubview:barFg];

            [NSLayoutConstraint activateConstraints:@[
                [logoWrap.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
                [logoWrap.centerYAnchor constraintEqualToAnchor:vc.view.centerYAnchor constant:-140],
                [logoWrap.widthAnchor constraintEqualToConstant:130],
                [logoWrap.heightAnchor constraintEqualToConstant:130],
                [dot.centerXAnchor constraintEqualToAnchor:logoWrap.centerXAnchor],
                [dot.centerYAnchor constraintEqualToAnchor:logoWrap.centerYAnchor],
                [dot.widthAnchor constraintEqualToConstant:16],
                [dot.heightAnchor constraintEqualToConstant:16],
                [brand.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
                [brand.topAnchor constraintEqualToAnchor:logoWrap.bottomAnchor constant:26],
                [sub.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
                [sub.topAnchor constraintEqualToAnchor:brand.bottomAnchor constant:6],
                [barBg.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
                [barBg.topAnchor constraintEqualToAnchor:sub.bottomAnchor constant:24],
                [barBg.widthAnchor constraintEqualToConstant:200],
                [barBg.heightAnchor constraintEqualToConstant:7],
                [barFg.leadingAnchor constraintEqualToAnchor:barBg.leadingAnchor],
                [barFg.topAnchor constraintEqualToAnchor:barBg.topAnchor],
                [barFg.bottomAnchor constraintEqualToAnchor:barBg.bottomAnchor],
                [barFg.widthAnchor constraintEqualToAnchor:barBg.widthAnchor multiplier:0.45],
            ]];

            UILabel *verLabel = [UILabel new];
            verLabel.text = @"v1.0.4";
            verLabel.font = [UIFont systemFontOfSize:12];
            verLabel.textColor = [UIColor colorWithRed:0.76 green:0.78 blue:0.82 alpha:1];
            verLabel.translatesAutoresizingMaskIntoConstraints = NO;
            [vc.view addSubview:verLabel];
            [NSLayoutConstraint activateConstraints:@[
                [verLabel.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
                [verLabel.bottomAnchor constraintEqualToAnchor:vc.view.safeAreaLayoutGuide.bottomAnchor
                                                      constant:-28],
            ]];

            UIWindow *w = [[UIWindow alloc] initWithWindowScene:scene];
            w.windowLevel = UIWindowLevelAlert + 3;
            w.rootViewController = vc;
            w.backgroundColor = vc.view.backgroundColor;
            gLaunchWindow = w;
            [w makeKeyAndVisible];

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.2 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [UIView animateWithDuration:0.4 animations:^{
                    w.alpha = 0;
                } completion:^(BOOL f) {
                    w.hidden = YES;
                    gLaunchWindow = nil;
                }];
            });
        } @catch (NSException *e) {
            MGLog(@"launch failed: %@", e);
        }
    });
}

// 独立 window，压在最上层
static UIWindow *gGateWindow = nil;
static MGGateVC *gGateVC = nil;

static UIWindowScene *MGFindScene(void) {
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:[UIWindowScene class]] &&
            s.activationState == UISceneActivationStateForegroundActive) {
            return (UIWindowScene *)s;
        }
    }
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:[UIWindowScene class]]) return (UIWindowScene *)s;
    }
    return nil;
}

static void MGShowGate(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            if (gGateWindow) { [gGateWindow makeKeyAndVisible]; return; }
            UIWindowScene *scene = MGFindScene();
            if (!scene) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ MGShowGate(); });
                return;
            }
            MGGateVC *vc = [MGGateVC new];
            vc.onPass = ^{
                [UIView animateWithDuration:0.25 animations:^{
                    gGateWindow.alpha = 0;
                } completion:^(BOOL f) {
                    gGateWindow.hidden = YES;
                    gGateWindow = nil;
                    gGateVC = nil;
                    [UIApplication.sharedApplication.keyWindow makeKeyAndVisible];
                    [[NSNotificationCenter defaultCenter] postNotificationName:@"MGGatePassed" object:nil];
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{
                        @try { MGShowHome(); } @catch (NSException *e) {}
                    });
                }];
            };
            UIWindow *w = [[UIWindow alloc] initWithWindowScene:scene];
            w.windowLevel = UIWindowLevelAlert + 1;
            w.rootViewController = vc;
            w.backgroundColor = UIColor.blackColor;
            gGateWindow = w; gGateVC = vc;
            [w makeKeyAndVisible];
        } @catch (NSException *e) {
            NSLog(@"[MyGate] show gate failed: %@", e);
        }
    });
}

// ============================ 首页改造 ============================
// 目标类来自原版：OKDHomeMusicController / CoreHomeLinkTarget
static NSString *MGRealExpiryText(void);
static NSString *MGReplace2099(NSString *t);

static void MGRewriteViewTree(UIView *v, int depth) {
    if (!v || depth > 12) return;
    @try {
        if ([v isKindOfClass:[UILabel class]]) {
            UILabel *l = (UILabel *)v;
            NSString *t = l.text ?: l.attributedText.string;
            if (t.length) {
                // 1) 把原版写死的 2099 假日期换成真实到期时间
                if ([t containsString:@"2099-12-31"]) {
                    MGLicense *lic = [MGLicense shared];
                    if (lic.expireAt > 0) {
                        NSDateFormatter *df = [NSDateFormatter new];
                        df.dateFormat = @"yyyy-MM-dd HH:mm:ss";
                        NSString *real = [df stringFromDate:
                                          [NSDate dateWithTimeIntervalSince1970:lic.expireAt]];
                        NSString *s2 = [t stringByReplacingOccurrencesOfString:@"2099-12-31 23:59:59"
                                                                    withString:real];
                        if (![s2 isEqualToString:t]) {
                            if (l.attributedText) {
                                NSMutableAttributedString *m = [l.attributedText mutableCopy];
                                [m.mutableString setString:s2];
                                l.attributedText = m;
                            } else {
                                l.text = s2;
                            }
                        }
                    }
                }
                // 2) 品牌名替换
                if ([t containsString:@"支持"] || [t containsString:@"Core"]) {
                    NSString *s1 = [t stringByReplacingOccurrencesOfString:@"支持" withString:kDisplayName];
                    l.text = [s1 stringByReplacingOccurrencesOfString:@"Core" withString:kDisplayName];
                }
            }
        } else if ([v isKindOfClass:[UIButton class]]) {
            UIButton *b = (UIButton *)v;
            NSString *t = [b titleForState:UIControlStateNormal];
            if (t.length && ([t containsString:@"社区"] || [t containsString:@"教程"])) {
                [b setTitle:[t stringByReplacingOccurrencesOfString:@"社区" withString:@"官方"]
                     forState:UIControlStateNormal];
            }
        }
        // 3) 遍历 layer 树，处理 CATextLayer 自绘文字
        Class catl = NSClassFromString(@"CATextLayer");
        if (catl) {
            @try {
                for (CALayer *sub in v.layer.sublayers) {
                    if (![sub isKindOfClass:catl]) continue;
                    id str = [sub valueForKey:@"string"];
                    if ([str isKindOfClass:[NSString class]] &&
                        [str rangeOfString:@"2099-12-31"].location != NSNotFound) {
                        NSString *real = MGRealExpiryText();
                        if (real) {
                            [sub setValue:[str stringByReplacingOccurrencesOfString:@"2099-12-31 23:59:59"
                                                                         withString:real]
                                   forKey:@"string"];
                        }
                    }
                }
            } @catch (NSException *e) {}
        }
        for (UIView *s in v.subviews) MGRewriteViewTree(s, depth + 1);
    } @catch (NSException *e) {
        // 单次遍历失败不影响主程序
    }
}

static void MGRewriteUI(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            for (UIWindow *w in UIApplication.sharedApplication.windows) {
                if (w == gGateWindow) continue;
                MGRewriteViewTree(w, 0);
            }
        } @catch (NSException *e) {}
    });
}

// ---- 浮窗诊断 ----
static UIWindow *gDiagWindow = nil;
static UIWindow *gCloseWindow = nil;

static UIWindow *MGTopWindow(void) {
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (w.windowLevel <= UIWindowLevelNormal + 1 && !w.hidden && w.rootViewController) return w;
    }
    return nil;
}

// 在最高层窗口放一个关闭按钮，点掉后隐藏目标
static void MGShowCloseButton(void (^onClose)(void)) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIWindowScene *scene = MGFindScene();
            if (!scene) return;
            if (!gCloseWindow) {
                UIWindow *w = [[UIWindow alloc] initWithWindowScene:scene];
                w.windowLevel = 10000100;   // 压过原版浮窗 (1e7)
                w.backgroundColor = [UIColor clearColor];
                UIViewController *vc = [UIViewController new];
                vc.view.backgroundColor = [UIColor clearColor];
                w.rootViewController = vc;
                gCloseWindow = w;
                [w makeKeyAndVisible];
            }
            UIView *host = gCloseWindow.rootViewController.view;
            for (UIView *old in host.subviews) [old removeFromSuperview];

            UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
            [btn setTitle:@"✕" forState:UIControlStateNormal];
            [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            btn.titleLabel.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
            btn.backgroundColor = [UIColor colorWithRed:0.06 green:0.06 blue:0.08 alpha:0.82];
            btn.layer.cornerRadius = 22;
            btn.layer.borderWidth = 1;
            btn.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.25].CGColor;
            btn.translatesAutoresizingMaskIntoConstraints = NO;

            __weak UIButton *weakBtn = btn;
            [btn addAction:[UIAction actionWithHandler:^(__kindof UIAction *a) {
                @try { if (onClose) onClose(); } @catch (NSException *e) {}
                weakBtn.hidden = YES;
            }] forControlEvents:UIControlEventTouchUpInside];

            [host addSubview:btn];
            [NSLayoutConstraint activateConstraints:@[
                [btn.trailingAnchor constraintEqualToAnchor:host.trailingAnchor constant:-18],
                [btn.topAnchor constraintEqualToAnchor:host.safeAreaLayoutGuide.topAnchor constant:56],
                [btn.widthAnchor constraintEqualToConstant:44],
                [btn.heightAnchor constraintEqualToConstant:44],
            ]];
        } @catch (NSException *e) {}
    });
}

// 记住「打开菜单」之前的状态，1 秒后比对出浮窗并挂关闭按钮
void MGWatchMenuClose(void) {
    UIWindow *main = MGTopWindow();
    NSArray *beforeWins = [UIApplication.sharedApplication.windows copy];
    NSArray *beforeSubs = main ? [main.subviews copy] : @[];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            // 1) 新增窗口
            for (UIWindow *w in UIApplication.sharedApplication.windows) {
                if ([beforeWins containsObject:w]) continue;
                if (w == gGateWindow || w == gLaunchWindow || w == gDiagWindow || w == gCloseWindow) continue;
                MGLog(@"[MGClose] new window %@ lv=%.0f", NSStringFromClass(w.class), w.windowLevel);
                return;
            }
            // 2) 主窗口新增的大视图
            UIWindow *m = MGTopWindow();
            if (!m) return;
            for (UIView *v in m.subviews) {
                if ([beforeSubs containsObject:v]) continue;
                CGSize s = v.bounds.size;
                if (s.width * s.height < 200 * 200) continue;
                MGLog(@"[MGClose] new view %@ frame=%@", NSStringFromClass(v.class),
                      NSStringFromCGRect(v.frame));
                return;
            }
        } @catch (NSException *e) {}
    });
}

// 判断是否是「原版浮窗」的窗口（排除我方窗口）
static BOOL MGIsMenuWindow(UIWindow *w) {
    if (!w) return NO;
    if (w == gGateWindow || w == gLaunchWindow || w == gCloseWindow || w == gDiagWindow) return NO;
    return w.windowLevel >= 5000;
}

// 供首页使用：判断原版浮窗（QXA131/QXA132）是否打开
BOOL MGMenuIsOpen(void) {
    @try {
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (MGIsMenuWindow(w) && !w.hidden) return YES;
        }
    } @catch (NSException *e) {}
    return NO;
}

// 供首页使用：关闭原版浮窗
void MGCloseMenuWindow(void) {
    @try {
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (MGIsMenuWindow(w)) {
                MGLog(@"[MGMenu] close %@ lv=%.0f", NSStringFromClass(w.class), w.windowLevel);
                w.hidden = YES;
            }
        }
    } @catch (NSException *e) {}
}

// 供首页使用：重新显示原版浮窗（菜单处于「开启」状态时，切页面回来了要恢复）
void MGShowMenuWindow(void) {
    @try {
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (!MGIsMenuWindow(w)) continue;
            if (w.hidden) {
                MGLog(@"[MGMenu] show %@ lv=%.0f", NSStringFromClass(w.class), w.windowLevel);
                w.hidden = NO;
            }
        }
    } @catch (NSException *e) {}
}

// 诊断：收集浮窗视图树文本
static void MGShowDiagText(NSString *text);

static void MGDescribeView(UIView *v, CGFloat winArea, int depth, NSMutableArray *out) {
    if (!v || depth > 6 || out.count > 26) return;
    @try {
        NSString *pad = [@"" stringByPaddingToLength:(NSUInteger)(depth * 2)
                                          withString:@" " startingAtIndex:0];
        NSString *cls = NSStringFromClass(v.class);
        NSString *extra = @"";
        if ([v isKindOfClass:[UILabel class]]) {
            UILabel *l = (UILabel *)v;
            if (l.text.length) extra = [NSString stringWithFormat:@" \"%@\"", l.text];
            if ([l.text containsString:@"XQSM"]) l.text = @"JUANMAO";
        } else if ([v isKindOfClass:[UIImageView class]]) {
            extra = @" [image]";
        }
        CGRect f = v.frame;
        [out addObject:[NSString stringWithFormat:@"%@%@ %.0fx%.0f%@",
                        pad, cls, f.size.width, f.size.height, extra]];
        for (UIView *c in v.subviews) MGDescribeView(c, winArea, depth + 1, out);
    } @catch (NSException *e) {}
}

void MGRestyleMenuWindow(void) {
    @try {
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (w.windowLevel < 5000 || w.hidden) continue;
            CGFloat area = w.bounds.size.width * w.bounds.size.height;
            NSMutableArray *lines = [NSMutableArray array];
            [lines addObject:[NSString stringWithFormat:@"%@ lv=%.0f",
                              NSStringFromClass(w.class), w.windowLevel]];
            MGDescribeView(w, area, 1, lines);
            NSLog(@"[MGRestyle] %@", [lines componentsJoinedByString:@" | "]);
            MGShowDiagText([lines componentsJoinedByString:@"\n"]);
            return;
        }
    } @catch (NSException *e) {}
}

// 递归收集：可见的、面积大的、非我方视图
static void MGCollectBigViews(UIView *v, NSMutableArray *out) {
    if (!v || v.hidden || v.alpha < 0.02) return;
    if (v.tag == 0x4D47) return;              // 我方视图标记，跳过整棵子树
    CGSize s = v.bounds.size;
    if (s.width * s.height > 300 * 400) [out addObject:v];
    for (UIView *c in v.subviews) MGCollectBigViews(c, out);
}

static void MGForceCloseOverlay(void) {
    @try {
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (w == gGateWindow || w == gLaunchWindow || w == gDiagWindow || w == gCloseWindow) continue;
            // 原版浮窗是 QXA131/QXA132，windowLevel = 1e7
            if (w.windowLevel >= 5000) {
                NSString *cls = NSStringFromClass(w.class);
                MGLog(@"[MGClose] hide window %@ lv=%.0f", cls, w.windowLevel);
                w.hidden = YES;
            }
        }
    } @catch (NSException *e) {}
}

// 让空白区域穿透的窗口：只有按钮自己接收触摸
@interface MGPassWindow : UIWindow
@end

@implementation MGPassWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    if (v == self || v == self.rootViewController.view) return nil;
    return v;
}
@end

// 常驻关闭按钮（最高层，始终可见）
void MGInstallCloseButton(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIWindowScene *scene = MGFindScene();
            if (!scene) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ MGInstallCloseButton(); });
                return;
            }
            if (!gCloseWindow) {
                MGPassWindow *w = [[MGPassWindow alloc] initWithWindowScene:scene];
                w.windowLevel = 10000100;   // 压过原版浮窗 (1e7)
                w.backgroundColor = [UIColor clearColor];
                UIViewController *vc = [UIViewController new];
                vc.view.backgroundColor = [UIColor clearColor];
                w.rootViewController = vc;
                gCloseWindow = w;
                w.hidden = NO;
            }
            UIView *host = gCloseWindow.rootViewController.view;
            host.tag = 0x4D47;
            for (UIView *old in host.subviews) [old removeFromSuperview];

            UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
            [btn setTitle:@"✕ 关闭菜单" forState:UIControlStateNormal];
            [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            btn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
            btn.backgroundColor = [UIColor colorWithRed:0.06 green:0.06 blue:0.08 alpha:0.85];
            btn.layer.cornerRadius = 20;
            btn.layer.borderWidth = 1;
            btn.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.28].CGColor;
            btn.translatesAutoresizingMaskIntoConstraints = NO;
            [btn addTarget:host action:NSSelectorFromString(@"mgNoop") forControlEvents:UIControlEventTouchUpInside];
            [btn addAction:[UIAction actionWithHandler:^(__kindof UIAction *a) {
                MGForceCloseOverlay();
            }] forControlEvents:UIControlEventTouchUpInside];

            [host addSubview:btn];
            [NSLayoutConstraint activateConstraints:@[
                [btn.trailingAnchor constraintEqualToAnchor:host.trailingAnchor constant:-14],
                [btn.topAnchor constraintEqualToAnchor:host.safeAreaLayoutGuide.topAnchor constant:52],
                [btn.widthAnchor constraintEqualToConstant:104],
                [btn.heightAnchor constraintEqualToConstant:40],
            ]];
            MGLog(@"[MGClose] button installed");
        } @catch (NSException *e) {
            MGLog(@"[MGClose] install failed: %@", e);
        }
    });
}

static void MGShowDiagText(NSString *text) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIWindowScene *scene = MGFindScene();
            if (!scene) return;
            if (!gDiagWindow) {
                MGPassWindow *w = [[MGPassWindow alloc] initWithWindowScene:scene];
                w.windowLevel = 10000200;   // 压过原版浮窗 (1e7)
                w.backgroundColor = [UIColor clearColor];
                UIViewController *vc = [UIViewController new];
                vc.view.backgroundColor = [UIColor clearColor];
                w.rootViewController = vc;
                gDiagWindow = w;
                w.hidden = NO;
            }
            UIView *host = gDiagWindow.rootViewController.view;
            for (UIView *old in host.subviews) [old removeFromSuperview];

            UILabel *l = [UILabel new];
            l.text = text;
            l.font = [UIFont boldSystemFontOfSize:12];
            l.textColor = [UIColor whiteColor];
            l.backgroundColor = [UIColor colorWithRed:0.0 green:0.0 blue:0.0 alpha:0.82];
            l.textAlignment = NSTextAlignmentCenter;
            l.numberOfLines = 0;
            l.layer.cornerRadius = 10;
            l.clipsToBounds = YES;
            l.translatesAutoresizingMaskIntoConstraints = NO;
            [host addSubview:l];
            [NSLayoutConstraint activateConstraints:@[
                [l.centerXAnchor constraintEqualToAnchor:host.centerXAnchor],
                [l.topAnchor constraintEqualToAnchor:host.safeAreaLayoutGuide.topAnchor constant:70],
                [l.widthAnchor constraintLessThanOrEqualToConstant:host.bounds.size.width - 30],
                [l.heightAnchor constraintGreaterThanOrEqualToConstant:40],
            ]];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(20 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [UIView animateWithDuration:0.3 animations:^{ l.alpha = 0; }
                                 completion:^(BOOL f) { [l removeFromSuperview]; }];
            });
        } @catch (NSException *e) {}
    });
}

static void MGDiagView(UIView *v, int depth) {
    if (depth > 6) return;
    NSString *pad = [@"" stringByPaddingToLength:depth * 2 withString:@" " startingAtIndex:0];
    NSLog(@"[MGDiag] %@%@ frame=%@", pad, NSStringFromClass(v.class),
          NSStringFromCGRect(v.frame));
    for (UIView *s in v.subviews) MGDiagView(s, depth + 1);
}

static void MGDiagWindows(void) {
    static int n = 0;
    if (n >= 4) return;
    n++;
    @try {
        NSMutableArray *lines = [NSMutableArray array];
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (w == gGateWindow || w == gLaunchWindow || w == gDiagWindow) continue;
            NSString *root = w.rootViewController ? NSStringFromClass(w.rootViewController.class) : @"nil";
            [lines addObject:[NSString stringWithFormat:@"%@ lv=%.0f root=%@",
                              NSStringFromClass(w.class), w.windowLevel, root]];
        }
        for (UIWindow *w in UIApplication.sharedApplication.windows) {
            if (w == gGateWindow || w == gLaunchWindow || w == gDiagWindow) continue;
            if (w.windowLevel > UIWindowLevelNormal + 1) continue;
            NSMutableArray *subs = [NSMutableArray array];
            for (UIView *s in w.subviews) [subs addObject:NSStringFromClass(s.class)];
            [lines addObject:[NSString stringWithFormat:@"subviews(%lu): %@",
                              (unsigned long)subs.count,
                              [subs componentsJoinedByString:@", "]]];
        }
        if (!lines.count) return;
        NSString *text = [lines componentsJoinedByString:@"\n"];
        NSLog(@"[MGDiag] ===== %@", text);
        MGShowDiagText(text);
    } @catch (NSException *e) {}
}

// ---- 顶部悬浮标签：显示服务器返回的真实到期时间 ----
static UILabel *gExpiryBadge = nil;

static NSString *MGExpiryText(NSString *fmt) {
    MGLicense *lic = [MGLicense shared];
    if (lic.expireAt <= 0) return nil;
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = fmt;
    return [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:lic.expireAt]];
}

static void MGShowExpiryBadge(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            MGLicense *lic = [MGLicense shared];
            if (lic.expireAt <= 0) return;

            if (gExpiryBadge && gExpiryBadge.superview) {
                gExpiryBadge.text = [NSString stringWithFormat:@"授权至 %@",
                                     MGExpiryText(@"yyyy-MM-dd HH:mm") ?: @"--"];
                [gExpiryBadge.superview bringSubviewToFront:gExpiryBadge];
                return;
            }

            UIWindow *win = nil;
            for (UIWindow *w in UIApplication.sharedApplication.windows) {
                if (w != gGateWindow && !w.hidden && w.windowLevel <= UIWindowLevelNormal) {
                    win = w;
                    break;
                }
            }
            if (!win) return;

            UILabel *l = [UILabel new];
            l.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
            l.textColor = [UIColor colorWithRed:0.55 green:0.95 blue:0.75 alpha:1];
            l.backgroundColor = [UIColor colorWithRed:0.05 green:0.10 blue:0.14 alpha:0.78];
            l.textAlignment = NSTextAlignmentCenter;
            l.layer.cornerRadius = 9;
            l.layer.borderWidth = 0.5;
            l.layer.borderColor = [UIColor colorWithRed:0.35 green:0.75 blue:0.60 alpha:0.6].CGColor;
            l.clipsToBounds = YES;
            l.translatesAutoresizingMaskIntoConstraints = NO;
            l.text = [NSString stringWithFormat:@"授权至 %@",
                      MGExpiryText(@"yyyy-MM-dd HH:mm") ?: @"--"];
            [win addSubview:l];
            [NSLayoutConstraint activateConstraints:@[
                [l.topAnchor constraintEqualToAnchor:win.safeAreaLayoutGuide.topAnchor constant:6],
                [l.trailingAnchor constraintEqualToAnchor:win.trailingAnchor constant:-14],
                [l.heightAnchor constraintEqualToConstant:22],
                [l.widthAnchor constraintGreaterThanOrEqualToConstant:160],
            ]];
            gExpiryBadge = l;
            MGLog(@"expiry badge added");
        } @catch (NSException *e) {
            MGLog(@"badge failed: %@", e);
        }
    });
}


// 首页横幅：原版 OKDHomeMusicController 的属性名不确定，valueForKey 可能抛异常，
// 因此这里不再 hook refreshHomeLayoutArtwork，只在视图树里安全替换文案。
static UIView *MGSafeRootView(id obj) {
    @try {
        id v = [obj valueForKey:@"_rootView"];
        if ([v isKindOfClass:[UIView class]]) return v;
    } @catch (NSException *e) {}
    @try {
        id v = [obj valueForKey:@"rootView"];
        if ([v isKindOfClass:[UIView class]]) return v;
    } @catch (NSException *e) {}
    return nil;
}

// 社区入口：openCommunity: 只有一个 id 参数，签名确定，保留 hook 但全程兜异常
static IMP gOrigOpenCommunity = NULL;
static void MGOpenCommunity(id self, SEL _cmd, id arg) {
    @try {
        NSURL *u = [NSURL URLWithString:@"https://t.me/your_channel"];
        if (u) {
            [UIApplication.sharedApplication openURL:u options:@{} completionHandler:nil];
        }
    } @catch (NSException *e) {
        MGLog(@"openCommunity failed: %@", e);
    }
}

// ---- 从源头拦截 2099 假日期：UILabel / CATextLayer / 子类 / layer 树 ----
static IMP gOrigSetText = NULL;
static IMP gOrigSetAttr = NULL;
static IMP gOrigLayerString = NULL;

static NSString *MGRealExpiryText(void) {
    MGLicense *lic = [MGLicense shared];
    if (lic.expireAt <= 0) return nil;
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    return [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:lic.expireAt]];
}

static NSString *MGReplace2099(NSString *t) {
    if (![t isKindOfClass:[NSString class]] || t.length == 0) return t;
    if ([t rangeOfString:@"2099-12-31"].location == NSNotFound) return t;
    NSString *real = MGRealExpiryText();
    if (!real) return t;
    return [t stringByReplacingOccurrencesOfString:@"2099-12-31 23:59:59" withString:real];
}

static void MGSetText(id self, SEL _cmd, NSString *text) {
    @try { text = MGReplace2099(text); } @catch (NSException *e) {}
    if (gOrigSetText) ((void (*)(id, SEL, id))gOrigSetText)(self, _cmd, text);
}

static void MGSetAttributedText(id self, SEL _cmd, NSAttributedString *text) {
    @try {
        if ([text isKindOfClass:[NSAttributedString class]] &&
            [text.string rangeOfString:@"2099-12-31"].location != NSNotFound) {
            NSString *real = MGRealExpiryText();
            if (real) {
                NSMutableAttributedString *m = [text mutableCopy];
                [m.mutableString setString:
                 [text.string stringByReplacingOccurrencesOfString:@"2099-12-31 23:59:59"
                                                         withString:real]];
                text = m;
            }
        }
    } @catch (NSException *e) {}
    if (gOrigSetAttr) ((void (*)(id, SEL, id))gOrigSetAttr)(self, _cmd, text);
}

// CATextLayer setString:
static void MGSetLayerString(id self, SEL _cmd, id str) {
    @try {
        if ([str isKindOfClass:[NSString class]]) {
            str = MGReplace2099((NSString *)str);
        } else if ([str isKindOfClass:[NSAttributedString class]]) {
            NSString *s = ((NSAttributedString *)str).string;
            if ([s rangeOfString:@"2099-12-31"].location != NSNotFound) {
                NSString *real = MGRealExpiryText();
                if (real) {
                    NSMutableAttributedString *m = [(NSAttributedString *)str mutableCopy];
                    [m.mutableString setString:
                     [s stringByReplacingOccurrencesOfString:@"2099-12-31 23:59:59"
                                                   withString:real]];
                    str = m;
                }
            }
        }
    } @catch (NSException *e) {}
    if (gOrigLayerString) ((void (*)(id, SEL, id))gOrigLayerString)(self, _cmd, str);
}

static void MGInstallTextHooks(void) {
    static BOOL installed = NO;
    if (installed) return;
    installed = YES;
    @try {
        Method m1 = class_getInstanceMethod([UILabel class], @selector(setText:));
        if (m1) {
            gOrigSetText = method_setImplementation(m1, (IMP)MGSetText);
            MGLog(@"hooked UILabel setText:");
        }
        Method m2 = class_getInstanceMethod([UILabel class], @selector(setAttributedText:));
        if (m2) {
            gOrigSetAttr = method_setImplementation(m2, (IMP)MGSetAttributedText);
            MGLog(@"hooked UILabel setAttributedText:");
        }
        // CATextLayer（用 NSClassFromString 避免链接 QuartzCore）
        Class catl = NSClassFromString(@"CATextLayer");
        if (catl) {
            Method m3 = class_getInstanceMethod(catl, NSSelectorFromString(@"setString:"));
            if (m3) {
                gOrigLayerString = method_setImplementation(m3, (IMP)MGSetLayerString);
                MGLog(@"hooked CATextLayer setString:");
            }
        }
        // 所有 UILabel 子类
        unsigned int total = 0, hooked = 0;
        Class *classes = objc_copyClassList(&total);
        if (classes) {
            for (unsigned int i = 0; i < total; i++) {
                Class c = classes[i];
                if (class_getSuperclass(c) != [UILabel class]) continue;
                Method m = class_getInstanceMethod(c, @selector(setText:));
                if (m) { method_setImplementation(m, (IMP)MGSetText); hooked++; }
                Method m2b = class_getInstanceMethod(c, @selector(setAttributedText:));
                if (m2b) { method_setImplementation(m2b, (IMP)MGSetAttributedText); }
            }
            free(classes);
        }
        MGLog(@"hooked %u UILabel subclasses", hooked);
    } @catch (NSException *e) {
        MGLog(@"text hooks failed: %@", e);
    }
}

static void MGInstallHooks(void) {
    MGInstallTextHooks();
    @try {
        Class c2 = NSClassFromString(@"CoreHomeLinkTarget");
        if (c2) {
            Method m = class_getInstanceMethod(c2, NSSelectorFromString(@"openCommunity:"));
            if (m) {
                gOrigOpenCommunity = method_getImplementation(m);
                method_setImplementation(m, (IMP)MGOpenCommunity);
                MGLog(@"hooked openCommunity:");
            }
        }
    } @catch (NSException *e) {
        MGLog(@"hook openCommunity failed: %@", e);
    }

    @try {
        [NSTimer scheduledTimerWithTimeInterval:2.5 repeats:YES block:^(NSTimer *t) {
            @try { MGRewriteUI(); } @catch (NSException *e) {}
            @try { MGShowExpiryBadge(); } @catch (NSException *e) {}
        }];
    } @catch (NSException *e) {
        MGLog(@"timer failed: %@", e);
    }
}

// ============================ 启动 ============================
extern void MGShowHome(void);

static void MGStart(void) {
    @try {
        MGLicense *lic = [MGLicense shared];
        if ([lic locallyValid]) {
            MGLog(@"local license ok until %.0f", lic.expireAt);
            MGInstallHooks();
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                @try { MGShowHome(); } @catch (NSException *e) {}
            });
            [[MGGate shared] heartbeat:^(BOOL ok) {
                if (!ok) { MGLog(@"heartbeat failed, keep local grace"); }
            }];
            return;
        }
        MGShowGate();
        MGInstallHooks();
    } @catch (NSException *e) {
        MGLog(@"start failed: %@", e);
        // 启动失败时也要保证能弹门禁，不阻断主程序
        @try { MGShowGate(); } @catch (NSException *e2) {}
    }
}

// 原版 CCCoreLicense 导出的符号，保留一个兼容位（当前没有任何模块引用它）
__attribute__((visibility("default"))) int CCCoreLicenseVerified = 1;

__attribute__((constructor))
static void MGInit(void) {
    // 注意：constructor 阶段 App 沙盒/Keychain 尚未就绪，
    // 这里只做无副作用的日志，所有 Keychain / UI 操作延后到主循环。
    MGLog(@"dylib loaded");
    // 尽早挂上文字拦截，赶在主界面 UILabel/CATextLayer 设值之前
    MGInstallTextHooks();
    // 启动画面：盖住原版「Core 引擎启动中」
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try { MGShowLaunch(); } @catch (NSException *e) {}
    });
    // 关闭菜单按钮：主界面出来后就常驻
    // （已改为首页卡片自身切换开关，不再需要右上角按钮）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        @try {
            MGLog(@"device=%s", MGDeviceID().UTF8String);
        } @catch (NSException *e) {
            MGLog(@"device id failed: %@", e);
        }
        MGStart();
        // 心跳
        [NSTimer scheduledTimerWithTimeInterval:kHeartbeatMin * 60 repeats:YES block:^(NSTimer *t) {
            [[MGGate shared] heartbeat:^(BOOL ok) {
                if (!ok && ![MGLicense shared].locallyValid) MGShowGate();
            }];
        }];
    });
}

// ============================ 说明 ============================
// 网络层已改为 CFStream 裸 socket（见 MGRawPostSync）：
//   · 不经过 NSURLSession → 不受 ATS 明文限制
//   · 不触发 CoreOffline 的 NSURLSessionTask hook → 不需要白名单 patch
// 以后换成域名 + TLS：改 kAPIHost / kAPIPort=443 / kUseTLS=YES 即可。
// 若要证书 pinning，在 kUseTLS 分支里把 kCFStreamSSLValidatesCertificateChain
// 关掉，再用 SecTrustEvaluateWithError 手工校验证书指纹。

