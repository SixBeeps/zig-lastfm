# 🎶 zig-lastfm 🎶

*You'll never guess what this is for!*

Zig library, interacts with the Last.fm API.

**WARNING**: This library was written by a JavaScript developer who hasn't written embedded code in a while. It is likely to be buggy, very memory inefficient, and not very idiomatic. Please feel free to contribute and make it better!

## Features + Todo
- [x] Extendable and generic methods
- [ ] Authentication
  - [x] Desktop / Web Flow
  - [ ] Mobile Flow
- [ ] Scrobbling
  - [x] Single Scrobble
  - [ ] Batch Scrobble

## Usage
### Initialization
```zig
const std = @import("std");
const http = @import("std").http;
const lastfm = @import("lastfm");

// Set up an allocator and HTTP client
const ally = std.heap.page_allocator;
var http_client = http.Client{
	.allocator = ally
};

// Create our LastFM client
const lastfm_client = LastFMClient{
	.api_key = "xxxxxxx",
	.api_secret = "xxxxxxx",
	.http_client = &http_client
};
defer lastfm_client.http_client.*.deinit();
```

### Authentication (Desktop Flow)
```zig
// Ask for a token
const token = try lastfm_client.getToken();
std.debug.print("Token = {s}\n", .{token});

// Prompt user to authorize the token
const login_url = try lastfm_client.getLoginUrl(token);
defer ally.free(login_url);
std.debug.print("Please visit the following URL to allow this application to access your Last.fm account.\n{s}\n\nPress enter when you are finished.\n", .{ login_url });
const stdin = std.io.getStdIn().reader();
try stdin.skipUntilDelimiterOrEof('\n');

// Try to exchange the token for a session
const session = try lastfm_client.getSession(token);
std.debug.print("Successfully logged in as {s} ({s}) with session key {s}\n", .{ session.name, if (session.subscribed()) "subscriber" else "basic", session.key });
```

### Scrobbling
#### Scrobble a single track
```zig
const scrobble = lastfm.Scrobble{
	.artist = "Cher",
	.track = "Believe",
	.timestamp = @divFloor(std.time.milliTimestamp(), 1000)
};

const successful = try lastfm_client.scrobbleOne();
```