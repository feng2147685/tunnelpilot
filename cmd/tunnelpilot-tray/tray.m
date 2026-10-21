#import <Cocoa/Cocoa.h>
#include <stdarg.h>
#include <stdio.h>
#include "tray.h"

// Go 侧导出的回调（由 cgo 的 //export 生成）
extern void goMenuAction(int action);

static NSStatusItem *gStatusItem = nil;
static NSMenu *gMenu = nil;
static void cfDrawTrayGlyph(int state);

static void tray_log(const char *fmt, ...) {
	FILE *fp = fopen("/tmp/tunnelpilot-tray-debug.log", "a");
	if (fp == NULL) {
		return;
	}
	va_list ap;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	fprintf(fp, "\n");
	fclose(fp);
}

@interface CFTrayTarget : NSObject
@end

@implementation CFTrayTarget
- (void)onItemClicked:(id)sender {
	NSMenuItem *item = (NSMenuItem *)sender;
	goMenuAction((int)[item tag]);
}
@end

static CFTrayTarget *gTarget = nil;

void tray_init(const char *title) {
	if (gStatusItem != nil) {
		return;
	}
	tray_log("tray_init: isMainThread=%d", [NSThread isMainThread] ? 1 : 0);

	NSApplication *app = [NSApplication sharedApplication];
	[app setActivationPolicy:NSApplicationActivationPolicyAccessory];
	[app finishLaunching];
	tray_log("tray_init: NSApp ready, policy=%ld", (long)[app activationPolicy]);

	gTarget = [[CFTrayTarget alloc] init];

	gStatusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
	tray_log("tray_init: statusItem=%p button=%p", gStatusItem, gStatusItem.button);
	if (gStatusItem.button == nil) {
		tray_log("tray_init: 错误 — statusItem.button 为 nil，系统版本可能不兼容");
	}
	NSImage *initialIcon = [NSImage imageWithSize:NSMakeSize(22, 22)
	                                     flipped:NO
	                              drawingHandler:^BOOL(NSRect dstRect) {
		cfDrawTrayGlyph(0);
		return YES;
	}];
	initialIcon.template = NO;
	gStatusItem.button.image = initialIcon;
	gStatusItem.button.imagePosition = NSImageOnly;
	gStatusItem.button.title = @"";
	(void)title;
	tray_log("tray_init: 图标已设置");

	gMenu = [[NSMenu alloc] init];

	NSMenuItem *statusLine = [[NSMenuItem alloc] initWithTitle:@"状态：未知" action:nil keyEquivalent:@""];
	[statusLine setTag:0];
	[statusLine setEnabled:NO];
	[gMenu addItem:statusLine];

	[gMenu addItem:[NSMenuItem separatorItem]];

	NSMenuItem *toggle = [[NSMenuItem alloc] initWithTitle:@"启动接管" action:@selector(onItemClicked:) keyEquivalent:@""];
	[toggle setTag:CF_TRAY_TOGGLE];
	[toggle setTarget:gTarget];
	[gMenu addItem:toggle];

	NSMenuItem *open = [[NSMenuItem alloc] initWithTitle:@"打开控制台" action:@selector(onItemClicked:) keyEquivalent:@""];
	[open setTag:CF_TRAY_OPEN];
	[open setTarget:gTarget];
	[gMenu addItem:open];

	[gMenu addItem:[NSMenuItem separatorItem]];

	NSMenuItem *quit = [[NSMenuItem alloc] initWithTitle:@"退出 TunnelPilot" action:@selector(onItemClicked:) keyEquivalent:@"q"];
	[quit setTag:CF_TRAY_QUIT];
	[quit setTarget:gTarget];
	[gMenu addItem:quit];

	gStatusItem.menu = gMenu;
	tray_log("tray_init: 完成，菜单项 %ld 个", (long)[gMenu numberOfItems]);
}

// 绘制菜单栏图标：字母 p + 右下角状态点
// state: 0=未接管(暗红) 1=已接管(绿) 2=切换中(黄色圆环)
static void cfDrawTrayGlyphWithInk(int state, NSColor *ink) {
	[ink setStroke];

	// 圆碗
	NSBezierPath *ring = [NSBezierPath bezierPathWithOvalInRect:NSMakeRect(6.8, 6.2, 12.6, 12.6)];
	ring.lineWidth = 2.7;
	[ring stroke];

	// 竖干
	NSBezierPath *stem = [NSBezierPath bezierPath];
	stem.lineWidth = 2.7;
	stem.lineCapStyle = NSLineCapStyleButt;
	[stem moveToPoint:NSMakePoint(8.15, 4.6)];
	[stem lineToPoint:NSMakePoint(8.15, 17.4)];
	[stem stroke];

	// 状态点
	NSRect dotRect = NSMakeRect(14.4, 2.0, 6.2, 6.2);
	if (state == 2) {
		NSBezierPath *ringDot = [NSBezierPath bezierPathWithOvalInRect:dotRect];
		ringDot.lineWidth = 1.9;
		[[NSColor systemYellowColor] setStroke];
		[ringDot stroke];
	} else {
		NSBezierPath *dot = [NSBezierPath bezierPathWithOvalInRect:dotRect];
		if (state == 1) {
			[[NSColor systemGreenColor] setFill];
		} else {
			[[NSColor colorWithSRGBRed:0.45 green:0.34 blue:0.34 alpha:1.0] setFill];
		}
		[dot fill];
	}
}

static void cfDrawTrayGlyph(int state) {
	cfDrawTrayGlyphWithInk(state, [NSColor labelColor]);
}

void tray_export_icons(const char *dir) {
	[NSApplication sharedApplication];
	const CGFloat scale = 4.0;
	const CGFloat canvas = 22.0;
	for (int state = 0; state < 3; state++) {
		NSImage *img = [[NSImage alloc] initWithSize:NSMakeSize(canvas * scale, canvas * scale)];
		[img lockFocus];
		[[NSColor colorWithSRGBRed:0.13 green:0.135 blue:0.15 alpha:1.0] setFill];
		NSRectFill(NSMakeRect(0, 0, canvas * scale, canvas * scale));
		NSAffineTransform *t = [NSAffineTransform transform];
		[t scaleBy:scale];
		[t concat];
		cfDrawTrayGlyphWithInk(state, [NSColor whiteColor]);
		[img unlockFocus];

		NSBitmapImageRep *rep = [NSBitmapImageRep imageRepWithData:[img TIFFRepresentation]];
		NSData *png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
		NSString *path = [NSString stringWithFormat:@"%s/tray-state-%d.png", dir, state];
		[png writeToFile:path atomically:YES];
	}
}

void tray_update(int running, int busy, const char *statusText, const char *toggleText) {
	NSString *status = [NSString stringWithUTF8String:statusText];
	NSString *toggle = [NSString stringWithUTF8String:toggleText];
	int state = busy ? 2 : (running ? 1 : 0);
	dispatch_async(dispatch_get_main_queue(), ^{
		if (gStatusItem == nil) {
			return;
		}
		NSImage *icon = [NSImage imageWithSize:NSMakeSize(22, 22)
		                              flipped:NO
		                       drawingHandler:^BOOL(NSRect dstRect) {
			cfDrawTrayGlyph(state);
			return YES;
		}];
		icon.template = NO;
		gStatusItem.button.image = icon;
		gStatusItem.button.imagePosition = NSImageOnly;
		gStatusItem.button.title = @"";

		if ([gMenu numberOfItems] > 0) {
			NSMenuItem *statusLine = [gMenu itemAtIndex:0];
			[statusLine setTitle:[NSString stringWithFormat:@"状态：%@", status]];
		}
		if ([gMenu numberOfItems] > 2) {
			NSMenuItem *toggleItem = [gMenu itemAtIndex:2];
			[toggleItem setTitle:[NSString stringWithString:toggle]];
			[toggleItem setEnabled:(busy ? NO : YES)];
		}
	});
}

void tray_run(void) {
	[NSApp run];
}

void tray_stop(void) {
	dispatch_async(dispatch_get_main_queue(), ^{
		[NSApp terminate:nil];
	});
}
