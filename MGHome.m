//
//  MGHome.m  —  极简高级风首页（覆盖在原版界面上）
//  按钮点击通过「找到原版对应控件 → sendActions」透传，不影响原版逻辑
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

// ===== 配色 =====
#define MG_BG      [UIColor colorWithRed:0.980 green:0.980 blue:0.984 alpha:1]
#define MG_INK     [UIColor colorWithRed:0.063 green:0.063 blue:0.078 alpha:1]
#define MG_SUB     [UIColor colorWithRed:0.549 green:0.569 blue:0.612 alpha:1]
#define MG_LINE    [UIColor colorWithRed:0.918 green:0.922 blue:0.941 alpha:1]
#define MG_CARD    [UIColor whiteColor]
#define MG_GREEN   [UIColor colorWithRed:0.039 green:0.620 blue:0.424 alpha:1]

// ===== 找原版控件并触发 =====
static UIControl *MGFindControl(UIView *v, NSString *title) {
    if (!v) return nil;
    if ([v isKindOfClass:[UIControl class]]) {
        UIControl *c = (UIControl *)v;
        NSString *t = nil;
        if ([c isKindOfClass:[UIButton class]]) {
            UIButton *b = (UIButton *)c;
            t = [b titleForState:UIControlStateNormal];
            if (!t.length) t = b.titleLabel.text;
            if (!t.length) t = [b attributedTitleForState:UIControlStateNormal].string;
        }
        if (!t.length) {
            @try { t = [c valueForKey:@"text"]; } @catch (NSException *e) {}
        }
        if ([t isKindOfClass:[NSString class]] && [t containsString:title]) return c;
    }
    for (UIView *s in v.subviews) {
        UIControl *r = MGFindControl(s, title);
        if (r) return r;
    }
    return nil;
}

static BOOL MGTrigger(NSString *title) {
    UIWindow *host = nil;
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (w.windowLevel <= UIWindowLevelNormal && !w.hidden) { host = w; break; }
    }
    if (!host) return NO;
    UIControl *c = MGFindControl(host, title);
    if (!c) return NO;
    [c sendActionsForControlEvents:UIControlEventTouchUpInside];
    return YES;
}

// ===== 小工具 =====
static UIView *MGCard(CGFloat radius) {
    UIView *v = [UIView new];
    v.backgroundColor = MG_CARD;
    v.layer.cornerRadius = radius;
    v.layer.borderWidth = 1.0 / UIScreen.mainScreen.scale;
    v.layer.borderColor = MG_LINE.CGColor;
    v.layer.shadowColor = [UIColor colorWithWhite:0 alpha:0.06].CGColor;
    v.layer.shadowOffset = CGSizeMake(0, 4);
    v.layer.shadowRadius = 12;
    v.layer.shadowOpacity = 1;
    v.translatesAutoresizingMaskIntoConstraints = NO;
    return v;
}

static UILabel *MGLabel(NSString *text, CGFloat size, BOOL bold, UIColor *color) {
    UILabel *l = [UILabel new];
    l.text = text;
    l.font = bold ? [UIFont boldSystemFontOfSize:size] : [UIFont systemFontOfSize:size];
    l.textColor = color;
    l.translatesAutoresizingMaskIntoConstraints = NO;
    return l;
}

// ===== 首页 VC =====
@interface MGHomeVC : UIViewController
@property (nonatomic, strong) UILabel *expiryValue;
@property (nonatomic, strong) UILabel *deviceValue;
@property (nonatomic, strong) UILabel *sysValue;
@property (nonatomic, strong) UILabel *menuTitle;
@property (nonatomic, strong) UILabel *menuSub;
@property (nonatomic, strong) UIView *menuBall;
@property (nonatomic, strong) CAGradientLayer *menuGradient;
@property (nonatomic, assign) BOOL menuOpen;
@property (nonatomic, assign) BOOL hasRestyled;
@property (nonatomic, assign) NSInteger zeroCount;
@property (nonatomic, strong) NSTimer *stateTimer;
- (void)refreshInfo;
- (void)tapMenu;
- (void)tapCell:(UIControl *)sender;
- (void)tapTutorial;
- (void)applyMenuState:(BOOL)open;
- (void)syncMenuState;
- (void)restyleIfNeeded;
- (void)startStateTimer;
@end

@implementation MGHomeVC

- (void)viewDidLoad {
    [super viewDidLoad];
    @try {
        self.view.backgroundColor = MG_BG;

        UIScrollView *scroll = [UIScrollView new];
        scroll.showsVerticalScrollIndicator = NO;
        scroll.translatesAutoresizingMaskIntoConstraints = NO;
        [self.view addSubview:scroll];

        UIView *content = [UIView new];
        content.translatesAutoresizingMaskIntoConstraints = NO;
        [scroll addSubview:content];

        // ---------- 标题 ----------
        UILabel *title = MGLabel(@"JUANMAO", 34, YES, MG_INK);
        [content addSubview:title];

        UILabel *sub = MGLabel(@"已授权 · 运行正常", 15, NO, MG_SUB);
        [content addSubview:sub];

        // ---------- 信息卡 ----------
        UIView *info = MGCard(22);
        [content addSubview:info];

        self.deviceValue = MGLabel(@"iPhone", 16, YES, MG_INK);
        self.sysValue = MGLabel(@"iOS", 16, YES, MG_INK);
        self.expiryValue = MGLabel(@"--", 16, YES, MG_GREEN);
        [self.deviceValue setContentHuggingPriority:UILayoutPriorityRequired
                                     forAxis:UILayoutConstraintAxisHorizontal];
        [self.sysValue setContentHuggingPriority:UILayoutPriorityRequired
                                     forAxis:UILayoutConstraintAxisHorizontal];
        [self.expiryValue setContentHuggingPriority:UILayoutPriorityRequired
                                     forAxis:UILayoutConstraintAxisHorizontal];

        NSArray *keys = @[@"设备", @"系统", @"授权至"];
        NSArray *vals = @[self.deviceValue, self.sysValue, self.expiryValue];
        NSMutableArray *rows = [NSMutableArray array];
        for (int i = 0; i < 3; i++) {
            UILabel *k = MGLabel(keys[i], 16, NO, MG_SUB);
            UILabel *v = (UILabel *)vals[i];
            [info addSubview:k];
            [info addSubview:v];
            UIView *line = [UIView new];
            line.backgroundColor = MG_LINE;
            line.translatesAutoresizingMaskIntoConstraints = NO;
            [info addSubview:line];
            if (i < 2) [rows addObject:line];
            [NSLayoutConstraint activateConstraints:@[
                [k.leadingAnchor constraintEqualToAnchor:info.leadingAnchor constant:22],
                [k.centerYAnchor constraintEqualToAnchor:v.centerYAnchor],
                [v.trailingAnchor constraintEqualToAnchor:info.trailingAnchor constant:-22],
                [line.leadingAnchor constraintEqualToAnchor:info.leadingAnchor constant:22],
                [line.trailingAnchor constraintEqualToAnchor:info.trailingAnchor constant:-22],
                [line.heightAnchor constraintEqualToConstant:1.0 / UIScreen.mainScreen.scale],
            ]];
        }
        // 三行纵向
        [NSLayoutConstraint activateConstraints:@[
            [self.deviceValue.topAnchor constraintEqualToAnchor:info.topAnchor constant:20],
            [self.sysValue.topAnchor constraintEqualToAnchor:self.deviceValue.bottomAnchor constant:22],
            [self.expiryValue.topAnchor constraintEqualToAnchor:self.sysValue.bottomAnchor constant:22],
            [self.expiryValue.bottomAnchor constraintEqualToAnchor:info.bottomAnchor constant:-20],
        ]];
        if (rows.count == 2) {
            UIView *l1 = rows[0], *l2 = rows[1];
            [NSLayoutConstraint activateConstraints:@[
                [l1.topAnchor constraintEqualToAnchor:self.deviceValue.bottomAnchor constant:10],
                [l2.topAnchor constraintEqualToAnchor:self.sysValue.bottomAnchor constant:10],
            ]];
        }

        // ---------- 主卡 ----------
        UIControl *main = [UIControl new];
        main.backgroundColor = [UIColor colorWithRed:0.054 green:0.054 blue:0.067 alpha:1];
        main.layer.cornerRadius = 22;
        main.translatesAutoresizingMaskIntoConstraints = NO;
        [main addTarget:self action:@selector(tapMenu) forControlEvents:UIControlEventTouchUpInside];
        [content addSubview:main];

        // 渐变球
        UIView *ball = [UIView new];
        ball.translatesAutoresizingMaskIntoConstraints = NO;
        ball.layer.cornerRadius = 26;
        ball.clipsToBounds = YES;
        CAGradientLayer *gl = [CAGradientLayer layer];
        gl.colors = @[(id)[UIColor colorWithRed:0.169 green:0.878 blue:0.541 alpha:1].CGColor,
                      (id)[UIColor colorWithRed:0.043 green:0.561 blue:0.388 alpha:1].CGColor];
        gl.startPoint = CGPointMake(0, 0);
        gl.endPoint = CGPointMake(1, 1);
        gl.frame = CGRectMake(0, 0, 52, 52);
        [ball.layer addSublayer:gl];
        self.menuGradient = gl;
        [main addSubview:ball];

        UILabel *mTitle = MGLabel(@"打开菜单", 22, YES, UIColor.whiteColor);
        UILabel *mSub = MGLabel(@"进入功能控制台", 13, NO,
                                [UIColor colorWithRed:0.557 green:0.576 blue:0.620 alpha:1]);
        self.menuTitle = mTitle;
        self.menuSub = mSub;
        self.menuBall = ball;
        [main addSubview:mTitle];
        [main addSubview:mSub];

        UILabel *arrow = MGLabel(@"›", 30, NO,
                                 [UIColor colorWithRed:0.353 green:0.373 blue:0.416 alpha:1]);
        [main addSubview:arrow];

        // ---------- 快捷功能 ----------
        UILabel *gridTitle = MGLabel(@"快捷功能", 18, YES, MG_INK);
        [content addSubview:gridTitle];
        UILabel *gridCount = MGLabel(@"6 项", 13, NO, MG_SUB);
        [content addSubview:gridCount];

        NSArray *names = @[@"查看公告", @"启动游戏", @"提交工单",
                           @"检查更新", @"工单进度", @"激活续时"];
        NSArray *colors = @[
            [UIColor colorWithRed:1.00 green:0.176 blue:0.420 alpha:1],
            [UIColor colorWithRed:0.486 green:0.361 blue:1.00 alpha:1],
            [UIColor colorWithRed:0.133 green:0.851 blue:0.941 alpha:1],
            [UIColor colorWithRed:1.00 green:0.541 blue:0.239 alpha:1],
            [UIColor colorWithRed:0.039 green:0.627 blue:0.431 alpha:1],
            [UIColor colorWithRed:0.776 green:0.957 blue:0.196 alpha:1],
        ];

        UIView *gridAnchor = gridTitle;
        NSMutableArray *gridViews = [NSMutableArray array];
        for (int i = 0; i < 6; i++) {
            UIView *cell = MGCard(18);
            cell.tag = 100 + i;
            [content addSubview:cell];
            [gridViews addObject:cell];

            UIView *dot = [UIView new];
            dot.backgroundColor = colors[i];
            dot.layer.cornerRadius = 15;
            dot.translatesAutoresizingMaskIntoConstraints = NO;
            [cell addSubview:dot];

            UIView *inner = [UIView new];
            inner.backgroundColor = [UIColor whiteColor];
            inner.layer.cornerRadius = 6;
            inner.translatesAutoresizingMaskIntoConstraints = NO;
            [dot addSubview:inner];

            UILabel *name = MGLabel(names[i], 14, YES, MG_INK);
            name.textAlignment = NSTextAlignmentCenter;
            [cell addSubview:name];

            [NSLayoutConstraint activateConstraints:@[
                [dot.centerXAnchor constraintEqualToAnchor:cell.centerXAnchor],
                [dot.topAnchor constraintEqualToAnchor:cell.topAnchor constant:18],
                [dot.widthAnchor constraintEqualToConstant:30],
                [dot.heightAnchor constraintEqualToConstant:30],
                [inner.centerXAnchor constraintEqualToAnchor:dot.centerXAnchor],
                [inner.centerYAnchor constraintEqualToAnchor:dot.centerYAnchor],
                [inner.widthAnchor constraintEqualToConstant:12],
                [inner.heightAnchor constraintEqualToConstant:12],
                [name.centerXAnchor constraintEqualToAnchor:cell.centerXAnchor],
                [name.topAnchor constraintEqualToAnchor:dot.bottomAnchor constant:12],
                [cell.heightAnchor constraintEqualToConstant:104],
            ]];

            UIControl *tap = [UIControl new];
            tap.translatesAutoresizingMaskIntoConstraints = NO;
            tap.tag = 200 + i;
            [tap addTarget:self action:@selector(tapCell:) forControlEvents:UIControlEventTouchUpInside];
            [cell addSubview:tap];
            [NSLayoutConstraint activateConstraints:@[
                [tap.leadingAnchor constraintEqualToAnchor:cell.leadingAnchor],
                [tap.trailingAnchor constraintEqualToAnchor:cell.trailingAnchor],
                [tap.topAnchor constraintEqualToAnchor:cell.topAnchor],
                [tap.bottomAnchor constraintEqualToAnchor:cell.bottomAnchor],
            ]];
        }

        // ---------- 教程 ----------
        UIView *tutorial = MGCard(18);
        [content addSubview:tutorial];
        UIView *tRed = [UIView new];
        tRed.backgroundColor = [UIColor colorWithRed:1.00 green:0.176 blue:0.420 alpha:1];
        tRed.layer.cornerRadius = 4;
        tRed.translatesAutoresizingMaskIntoConstraints = NO;
        [tutorial addSubview:tRed];
        UIView *tBlue = [UIView new];
        tBlue.backgroundColor = [UIColor colorWithRed:0.133 green:0.851 blue:0.941 alpha:1];
        tBlue.layer.cornerRadius = 4;
        tBlue.translatesAutoresizingMaskIntoConstraints = NO;
        [tutorial addSubview:tBlue];
        UILabel *tTitle = MGLabel(@"使用教程", 16, YES, MG_INK);
        UILabel *tSub = MGLabel(@"3 分钟上手", 12, NO, MG_SUB);
        [tutorial addSubview:tTitle];
        [tutorial addSubview:tSub];
        UILabel *tArrow = MGLabel(@"›", 26, NO,
                                  [UIColor colorWithRed:0.769 green:0.784 blue:0.824 alpha:1]);
        [tutorial addSubview:tArrow];

        UIControl *tutorialTap = [UIControl new];
        tutorialTap.translatesAutoresizingMaskIntoConstraints = NO;
        [tutorialTap addTarget:self action:@selector(tapTutorial)
             forControlEvents:UIControlEventTouchUpInside];
        [tutorial addSubview:tutorialTap];

        // ---------- 底部 ----------
        UILabel *ver = MGLabel(@"v1.0.4", 11, NO,
                               [UIColor colorWithRed:0.725 green:0.741 blue:0.784 alpha:1]);
        UILabel *online = MGLabel(@"服务正常", 11, NO, MG_GREEN);
        [content addSubview:ver];
        [content addSubview:online];

        // ---------- 布局 ----------
        UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
        [NSLayoutConstraint activateConstraints:@[
            [scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
            [scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
            [scroll.topAnchor constraintEqualToAnchor:safe.topAnchor],
            [scroll.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],

            [content.leadingAnchor constraintEqualToAnchor:scroll.leadingAnchor],
            [content.trailingAnchor constraintEqualToAnchor:scroll.trailingAnchor],
            [content.topAnchor constraintEqualToAnchor:scroll.topAnchor],
            [content.bottomAnchor constraintEqualToAnchor:scroll.bottomAnchor],
            [content.widthAnchor constraintEqualToAnchor:scroll.widthAnchor],

            [title.topAnchor constraintEqualToAnchor:content.topAnchor constant:28],
            [title.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:24],
            [sub.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:4],
            [sub.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],

            [info.topAnchor constraintEqualToAnchor:sub.bottomAnchor constant:22],
            [info.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:20],
            [info.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-20],

            [main.topAnchor constraintEqualToAnchor:info.bottomAnchor constant:16],
            [main.leadingAnchor constraintEqualToAnchor:info.leadingAnchor],
            [main.trailingAnchor constraintEqualToAnchor:info.trailingAnchor],
            [main.heightAnchor constraintEqualToConstant:96],

            [ball.leadingAnchor constraintEqualToAnchor:main.leadingAnchor constant:20],
            [ball.centerYAnchor constraintEqualToAnchor:main.centerYAnchor],
            [ball.widthAnchor constraintEqualToConstant:52],
            [ball.heightAnchor constraintEqualToConstant:52],

            [mTitle.leadingAnchor constraintEqualToAnchor:ball.trailingAnchor constant:16],
            [mTitle.topAnchor constraintEqualToAnchor:main.topAnchor constant:26],
            [mSub.leadingAnchor constraintEqualToAnchor:mTitle.leadingAnchor],
            [mSub.topAnchor constraintEqualToAnchor:mTitle.bottomAnchor constant:2],

            [arrow.trailingAnchor constraintEqualToAnchor:main.trailingAnchor constant:-20],
            [arrow.centerYAnchor constraintEqualToAnchor:main.centerYAnchor],

            [gridTitle.topAnchor constraintEqualToAnchor:main.bottomAnchor constant:28],
            [gridTitle.leadingAnchor constraintEqualToAnchor:info.leadingAnchor],
            [gridCount.centerYAnchor constraintEqualToAnchor:gridTitle.centerYAnchor],
            [gridCount.trailingAnchor constraintEqualToAnchor:info.trailingAnchor],
        ]];

        // 3 列网格
        CGFloat gap = 10;
        UIView *prev = nil;
        for (int i = 0; i < 6; i++) {
            UIView *cell = gridViews[i];
            int col = i % 3;
            int row = i / 3;
            if (col == 0) {
                [NSLayoutConstraint activateConstraints:@[
                    [cell.leadingAnchor constraintEqualToAnchor:info.leadingAnchor],
                ]];
                if (row == 0) {
                    [NSLayoutConstraint activateConstraints:@[
                        [cell.topAnchor constraintEqualToAnchor:gridTitle.bottomAnchor constant:12],
                    ]];
                } else {
                    UIView *up = gridViews[i - 3];
                    [NSLayoutConstraint activateConstraints:@[
                        [cell.topAnchor constraintEqualToAnchor:up.bottomAnchor constant:gap],
                    ]];
                }
            } else {
                UIView *left = gridViews[i - 1];
                [NSLayoutConstraint activateConstraints:@[
                    [cell.leadingAnchor constraintEqualToAnchor:left.trailingAnchor constant:gap],
                    [cell.topAnchor constraintEqualToAnchor:left.topAnchor],
                    [cell.widthAnchor constraintEqualToAnchor:left.widthAnchor],
                ]];
            }
            if (col == 2) {
                [NSLayoutConstraint activateConstraints:@[
                    [cell.trailingAnchor constraintEqualToAnchor:info.trailingAnchor],
                ]];
            }
            prev = cell;
        }

        // 教程
        UIView *lastRow = gridViews[5];
        [NSLayoutConstraint activateConstraints:@[
            [tutorial.topAnchor constraintEqualToAnchor:lastRow.bottomAnchor constant:16],
            [tutorial.leadingAnchor constraintEqualToAnchor:info.leadingAnchor],
            [tutorial.trailingAnchor constraintEqualToAnchor:info.trailingAnchor],
            [tutorial.heightAnchor constraintEqualToConstant:64],

            [tRed.leadingAnchor constraintEqualToAnchor:tutorial.leadingAnchor constant:18],
            [tRed.centerYAnchor constraintEqualToAnchor:tutorial.centerYAnchor],
            [tRed.widthAnchor constraintEqualToConstant:22],
            [tRed.heightAnchor constraintEqualToConstant:26],
            [tBlue.leadingAnchor constraintEqualToAnchor:tRed.leadingAnchor constant:12],
            [tBlue.centerYAnchor constraintEqualToAnchor:tutorial.centerYAnchor],
            [tBlue.widthAnchor constraintEqualToConstant:10],
            [tBlue.heightAnchor constraintEqualToConstant:26],

            [tTitle.leadingAnchor constraintEqualToAnchor:tRed.trailingAnchor constant:14],
            [tTitle.topAnchor constraintEqualToAnchor:tutorial.topAnchor constant:14],
            [tSub.leadingAnchor constraintEqualToAnchor:tTitle.leadingAnchor],
            [tSub.topAnchor constraintEqualToAnchor:tTitle.bottomAnchor constant:1],

            [tArrow.trailingAnchor constraintEqualToAnchor:tutorial.trailingAnchor constant:-18],
            [tArrow.centerYAnchor constraintEqualToAnchor:tutorial.centerYAnchor],

            [tutorialTap.leadingAnchor constraintEqualToAnchor:tutorial.leadingAnchor],
            [tutorialTap.trailingAnchor constraintEqualToAnchor:tutorial.trailingAnchor],
            [tutorialTap.topAnchor constraintEqualToAnchor:tutorial.topAnchor],
            [tutorialTap.bottomAnchor constraintEqualToAnchor:tutorial.bottomAnchor],

            [ver.leadingAnchor constraintEqualToAnchor:info.leadingAnchor],
            [ver.topAnchor constraintEqualToAnchor:tutorial.bottomAnchor constant:8],
            [online.trailingAnchor constraintEqualToAnchor:info.trailingAnchor],
            [online.centerYAnchor constraintEqualToAnchor:ver.centerYAnchor],
            [ver.bottomAnchor constraintEqualToAnchor:content.bottomAnchor constant:-24],
        ]];

        [self refreshInfo];
        [self startStateTimer];
    } @catch (NSException *e) {
        NSLog(@"[MGHome] ui failed: %@", e);
    }
}

- (void)refreshInfo {
    @try {
        UIDevice *d = UIDevice.currentDevice;
        self.deviceValue.text = d.model ?: @"iPhone";
        self.sysValue.text = [NSString stringWithFormat:@"iOS %@", d.systemVersion ?: @"-"];
    } @catch (NSException *e) {}

    @try {
        Class cls = NSClassFromString(@"MGLicense");
        if (cls) {
            id lic = ((id (*)(id, SEL))objc_msgSend)((id)cls, @selector(shared));
            NSTimeInterval exp = ((NSTimeInterval (*)(id, SEL))objc_msgSend)(lic, @selector(expireAt));
            if (exp > 0) {
                NSDateFormatter *df = [NSDateFormatter new];
                df.dateFormat = @"yyyy-MM-dd HH:mm";
                self.expiryValue.text = [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:exp]];
            }
        }
    } @catch (NSException *e) {}
}

- (void)tapMenu {
    extern BOOL MGShowMenuWindow(void);
    extern void MGCloseMenuWindow(void);

    if (self.menuOpen) {
        // 关闭：把浮球窗口层级压到首页下面（视觉上消失，窗口不销毁）
        [self applyMenuState:NO];
        @try { MGCloseMenuWindow(); } @catch (NSException *e) {}
    } else {
        // 打开：恢复层级 + 触发原版，两个都做（双保险，幂等安全）
        [self applyMenuState:YES];
        @try { MGShowMenuWindow(); } @catch (NSException *e) {}
        @try { MGTrigger(@"打开菜单"); } @catch (NSException *e) {}
    }
}

- (void)restyleIfNeeded {
    // 浮窗内容由 ImGui 每帧重绘，外部无法改样式；诊断已完成，这里不再做任何事。
    return;
}

- (void)applyMenuState:(BOOL)open {
    self.menuOpen = open;
    self.menuTitle.text = open ? @"关闭菜单" : @"打开菜单";
    self.menuSub.text = open ? @"收起功能控制台" : @"进入功能控制台";
    if (open) {
        self.menuGradient.colors = @[
            (id)[UIColor colorWithRed:1.00 green:0.286 blue:0.478 alpha:1].CGColor,
            (id)[UIColor colorWithRed:0.780 green:0.118 blue:0.322 alpha:1].CGColor
        ];
    } else {
        self.menuGradient.colors = @[
            (id)[UIColor colorWithRed:0.169 green:0.878 blue:0.541 alpha:1].CGColor,
            (id)[UIColor colorWithRed:0.043 green:0.561 blue:0.388 alpha:1].CGColor
        ];
    }
}

- (void)syncMenuState {
    // 完全退出：不碰任何窗口，不自动改按钮。
    // 按钮状态完全由用户点击决定（toggle 由原版自己处理）。
}

- (void)startStateTimer {
    if (self.stateTimer) return;
    __weak typeof(self) weakSelf = self;
    self.stateTimer = [NSTimer scheduledTimerWithTimeInterval:0.6 repeats:YES block:^(NSTimer *t) {
        @try { [weakSelf syncMenuState]; } @catch (NSException *e) {}
    }];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self startStateTimer];
}

- (void)dealloc {
    [self.stateTimer invalidate];
}

- (void)tapCell:(UIControl *)sender {
    NSArray *names = @[@"查看公告", @"启动游戏", @"提交工单",
                       @"检查更新", @"工单进度", @"激活续时"];
    int idx = (int)sender.tag - 200;
    if (idx >= 0 && idx < names.count) MGTrigger(names[idx]);
}

- (void)tapTutorial {
    MGTrigger(@"教程");
}

@end

// ===== 挂载 =====
static MGHomeVC *gHome = nil;

void MGShowHome(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            if (gHome) return;
            UIWindow *host = nil;
            for (UIWindow *w in UIApplication.sharedApplication.windows) {
                if (w.windowLevel <= UIWindowLevelNormal && !w.hidden && w.rootViewController) {
                    host = w;
                    break;
                }
            }
            if (!host) return;
            UIViewController *root = host.rootViewController;
            MGHomeVC *vc = [MGHomeVC new];
            vc.view.tag = 0x4D47;
            [root addChildViewController:vc];
            vc.view.frame = root.view.bounds;
            vc.view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
            [root.view addSubview:vc.view];
            [vc didMoveToParentViewController:root];
            gHome = vc;
            NSLog(@"[MGHome] attached");
        } @catch (NSException *e) {
            NSLog(@"[MGHome] attach failed: %@", e);
        }
    });
}
