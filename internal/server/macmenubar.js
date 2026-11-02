// mustra menu bar helper (macOS).
//
// Runs as a LaunchAgent in the logged-in user's GUI session. It has to: the
// agent itself is a LaunchDaemon running as root with no session, and a
// process with no session cannot draw in the menu bar. Same split as the
// Windows tray helper, for the same reason.
//
// JXA rather than a compiled app because every agent binary is built with
// CGO_ENABLED=0 so it can cross-compile from Linux, and NSStatusItem lives
// in AppKit, which is only reachable through cgo. Compiling this would mean
// a macOS build machine in the release pipeline and an unsigned binary for
// Gatekeeper to argue with. osascript is already on every Mac, and the
// installer already writes a script-backed .app for Self Service.
//
// Everything it shows comes from the agent's own loopback API. It holds no
// state, talks to nothing but 127.0.0.1, and if the agent is not running it
// says so rather than disappearing.

ObjC.import('Cocoa');

var SS = 'http://127.0.0.1:8137';
var SELF_SERVICE_APP = '/Applications/Mustra Self Service.app';

var shell = Application.currentApplication();
shell.includeStandardAdditions = true;

function sh(cmd) {
    try {
        return shell.doShellScript(cmd);
    } catch (e) {
        return '';
    }
}

function notify(title, text) {
    sh('/usr/bin/osascript -e ' + quoted('display notification ' + quoted(text) +
        ' with title ' + quoted(title)));
}

// AppleScript string literal, for text that reaches osascript.
function quoted(s) {
    return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

// state asks the agent what it is doing. This is the endpoint the tray
// helpers poll: it answers from memory and does not make the agent talk to
// the control plane, which matters because this runs on every menu open.
function state() {
    var raw = sh('/usr/bin/curl -fsS --max-time 2 ' + SS + '/api/notification');
    if (!raw) return null;
    try {
        return JSON.parse(raw);
    } catch (e) {
        return null;
    }
}

ObjC.registerSubclass({
    name: 'MustraMenuHandler',
    superclass: 'NSObject',
    methods: {
        // Rebuilt every time the menu is opened rather than polled on a
        // timer: the numbers are only ever read at the moment somebody
        // looks at them, so a timer would spend the whole day refreshing a
        // menu nobody has open.
        'menuNeedsUpdate:': {
            types: ['void', ['id']],
            implementation: function (menu) { rebuild(menu); },
        },
        'openSelfService:': {
            types: ['void', ['id']],
            implementation: function () {
                sh('/usr/bin/open -a ' + quoted(SELF_SERVICE_APP));
            },
        },
        'checkIn:': {
            types: ['void', ['id']],
            implementation: function () {
                // The agent wants its per-launch session token and a JSON
                // body on every POST (internal/agent/selfservice_guard.go).
                var token = '';
                try { token = JSON.parse(sh('/usr/bin/curl -fsS --max-time 2 ' + SS + '/api/session')).token || ''; } catch (e) {}
                var out = token && /^[0-9a-f]+$/.test(token) ? sh('/usr/bin/curl -fsS --max-time 8 -X POST -H "Content-Type: application/json" -H "X-Mustra-Token: ' +
                    token + '" --data "{}" ' + SS + '/api/checkin') : '';
                if (out) {
                    notify('mustra', 'Checked in with the server.');
                } else {
                    notify('mustra', 'Could not reach the agent on this Mac.');
                }
            },
        },
        'copyDetails:': {
            types: ['void', ['id']],
            implementation: function () {
                var s = state();
                var text = s
                    ? 'host ' + s.hostname + ' · agent ' + s.agent_version +
                      ' · ' + (s.connected ? 'connected' : 'offline')
                    : 'the mustra agent is not responding on this Mac';
                var pb = $.NSPasteboard.generalPasteboard;
                pb.clearContents;
                pb.setStringForType($(text), $.NSPasteboardTypeString);
                notify('mustra', 'Copied.');
            },
        },
        // Quits this icon, not the agent. The wording says so, because a
        // menu item called Exit on a management tool reads like a way to
        // turn the management off, and somebody choosing it should not be
        // surprised either way.
        'quitHelper:': {
            types: ['void', ['id']],
            implementation: function () { $.NSApp.terminate(null); },
        },
    },
});

var handler = $.MustraMenuHandler.alloc.init;

function infoItem(title) {
    var item = $.NSMenuItem.alloc.initWithTitleActionKeyEquivalent($(title), $(''), $(''));
    item.setEnabled(false);
    return item;
}

function actionItem(title, selector) {
    var item = $.NSMenuItem.alloc.initWithTitleActionKeyEquivalent($(title), selector, $(''));
    item.setTarget(handler);
    return item;
}

function rebuild(menu) {
    menu.removeAllItems;

    var s = state();
    if (s) {
        menu.addItem(infoItem(s.connected ? 'Connected' : 'Not connected to the server'));
        menu.addItem(infoItem('Agent ' + s.agent_version));
        menu.addItem(infoItem(s.hostname));
    } else {
        menu.addItem(infoItem('The agent is not running on this Mac'));
    }

    menu.addItem($.NSMenuItem.separatorItem);
    menu.addItem(actionItem('Open Self Service', 'openSelfService:'));
    menu.addItem(actionItem('Check in now', 'checkIn:'));
    menu.addItem(actionItem('Copy details', 'copyDetails:'));
    menu.addItem($.NSMenuItem.separatorItem);
    menu.addItem(actionItem('Quit menu bar icon', 'quitHelper:'));

    updateTitle(s);
}

var statusItem = $.NSStatusBar.systemStatusBar
    .statusItemWithLength($.NSVariableStatusItemLength);

// The mustra mark, drawn rather than fetched.
//
// The same path the console draws: M20 76 V24 L50 60 L80 24 V76, a 16-wide
// round-capped stroke in a 100 box. Drawing it means no asset to download,
// cache and keep in step with the installer, and it is crisp at whatever
// size the menu bar happens to be.
//
// Marked as a template image, which is what makes macOS treat the alpha as
// the shape and choose the colour itself: dark on a light menu bar, light
// on a dark one, inverted while the menu is open. A coloured PNG would be
// wrong in at least one of those three.
function brandImage(strength) {
    var BOX = 18;
    var scale = BOX / 100;
    var image = $.NSImage.alloc.initWithSize($.NSMakeSize(BOX, BOX));

    image.lockFocus;
    var path = $.NSBezierPath.bezierPath;
    path.setLineWidth(16 * scale);
    // Numeric rather than $.NSLineCapStyleRound: the enum was renamed
    // between SDKs and an undefined constant here draws the wrong cap or
    // throws, where the value 1 has meant round in every version.
    path.setLineCapStyle(1);
    path.setLineJoinStyle(1);

    // SVG counts y downwards and NSImage counts it up, so the axis flips.
    function at(x, y) {
        return $.NSMakePoint(x * scale, (100 - y) * scale);
    }
    path.moveToPoint(at(20, 76));
    path.lineToPoint(at(20, 24));
    path.lineToPoint(at(50, 60));
    path.lineToPoint(at(80, 24));
    path.lineToPoint(at(80, 76));

    $.NSColor.colorWithCalibratedWhiteAlpha(0, strength).setStroke;
    path.stroke;
    image.unlockFocus;

    image.setTemplate(true);
    return image;
}

// Connection state is carried by how solid the mark is rather than by a
// different glyph: faded reads as "not talking to anything" without needing
// a legend, and the menu says it in words on its first line.
function updateTitle(s) {
    var button = statusItem.button;
    if (button.isNil()) return;
    var strength = s ? (s.connected ? 1.0 : 0.4) : 0.25;
    try {
        button.setImage(brandImage(strength));
        button.setTitle($(''));
    } catch (e) {
        // If anything in the drawing above is unavailable, fall back to a
        // character. No icon at all is worse than a plain one: there would
        // be nothing left in the menu bar to click.
        button.setImage(null);
        button.setTitle($(s ? (s.connected ? '◉' : '○') : '◌'));
    }
}

var menu = $.NSMenu.alloc.init;
menu.setDelegate(handler);
// The menu is rebuilt on open; this is what is there before the first one.
rebuild(menu);
statusItem.setMenu(menu);

var app = $.NSApplication.sharedApplication;
// Accessory: a menu bar item with no Dock icon and no menu bar of its own.
app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
app.run;
