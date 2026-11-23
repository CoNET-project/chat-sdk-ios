#import <UIKit/UIKit.h>
#import <Security/Security.h>

// Entitled TEST_HOST for RealKeychain settle R1/R2.
// Mirrors C2Host: write Documents/c2-result.json at launch so environmentProbeError can see a prior entitlement probe.
// Bundle: com.beamio.test.realkeychain.host · group: com.beamio.test.realkeychain

@interface SettleAppDelegate : UIResponder <UIApplicationDelegate>
@end
@implementation SettleAppDelegate
@end

@interface SettleSceneDelegate : UIResponder <UIWindowSceneDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

static NSString *SecMsg(OSStatus s) {
	CFStringRef cf = SecCopyErrorMessageString(s, NULL);
	if (!cf) return [NSString stringWithFormat:@"status=%d", (int)s];
	NSString *out = [(__bridge NSString *)cf copy];
	CFRelease(cf);
	return out;
}

static void WriteProbeJSON(NSDictionary *payload) {
	NSURL *docs = [[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] firstObject];
	if (!docs) return;
	NSURL *url = [docs URLByAppendingPathComponent:@"c2-result.json"];
	NSData *data = [NSJSONSerialization dataWithJSONObject:payload options:NSJSONWritingPrettyPrinted error:nil];
	if (data) [data writeToURL:url atomically:YES];
}

static void RunHostProbe(void) {
	NSString *service = [NSString stringWithFormat:@"com.beamio.beamio.chat-wallet.realkc-probe.%@", NSUUID.UUID.UUIDString];
	NSString *account = @"c2-host-probe";
	NSData *bytes = [@"settle-host-probe-v1" dataUsingEncoding:NSUTF8StringEncoding];
	int secCalls = 0;

	NSMutableDictionary *base = [@{
		(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
		(__bridge id)kSecAttrService: service,
		(__bridge id)kSecAttrAccount: account,
	} mutableCopy];

	NSMutableDictionary *add = [base mutableCopy];
	add[(__bridge id)kSecValueData] = bytes;
	add[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
	add[(__bridge id)kSecAttrSynchronizable] = @NO;
	secCalls += 1;
	OSStatus addStatus = SecItemAdd((__bridge CFDictionaryRef)add, NULL);

	NSMutableDictionary *query = [base mutableCopy];
	query[(__bridge id)kSecReturnData] = @YES;
	query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
	query[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUIFail;
	CFTypeRef item = NULL;
	secCalls += 1;
	OSStatus copyStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &item);
	NSData *readBack = (__bridge_transfer NSData *)item;
	BOOL equal = readBack && [readBack isEqualToData:bytes];

	NSMutableDictionary *del = [base mutableCopy];
	secCalls += 1;
	OSStatus delStatus = SecItemDelete((__bridge CFDictionaryRef)del);

	NSDictionary *payload = @{
		@"probe": @"settle-host",
		@"add_status": @(addStatus),
		@"add_msg": SecMsg(addStatus) ?: @"",
		@"copy_status": @(copyStatus),
		@"copy_msg": SecMsg(copyStatus) ?: @"",
		@"bytes_equal": @(equal),
		@"delete_status": @(delStatus),
		@"sec_calls": @(secCalls),
		@"service_kind": @"synthetic",
		@"access_group": @"not_set",
		@"bundle": [[NSBundle mainBundle] bundleIdentifier] ?: @"",
		@"utc": [[NSISO8601DateFormatter new] stringFromDate:[NSDate date]] ?: @"",
	};
	WriteProbeJSON(payload);
	NSLog(@"SETTLE_HOST_PROBE add=%d copy=%d equal=%d del=%d", (int)addStatus, (int)copyStatus, (int)equal, (int)delStatus);
}

@implementation SettleSceneDelegate
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)connectionOptions {
	(void)session; (void)connectionOptions;
	if (![scene isKindOfClass:[UIWindowScene class]]) return;
	UIWindowScene *ws = (UIWindowScene *)scene;
	self.window = [[UIWindow alloc] initWithWindowScene:ws];
	UIViewController *root = [UIViewController new];
	root.view.backgroundColor = [UIColor systemBackgroundColor];
	UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(24, 120, 300, 40)];
	label.text = @"SettleHost";
	label.font = [UIFont preferredFontForTextStyle:UIFontTextStyleTitle1];
	[root.view addSubview:label];
	self.window.rootViewController = root;
	[self.window makeKeyAndVisible];
	RunHostProbe();
}
@end

int main(int argc, char *argv[]) {
	@autoreleasepool {
		return UIApplicationMain(argc, argv, nil, NSStringFromClass([SettleAppDelegate class]));
	}
}
