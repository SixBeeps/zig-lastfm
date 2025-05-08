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
```zig
const std = @import("std");
const lastfm = @import("lastfm.zig");

// Set up an allocator and HTTP client
const ally = std.heap.page_allocator;
var http_client = http.Client{
	.allocator = ally
};

// Create our LastFM client
const lastfm_client = LastFMClient{
	.api_key = sensitive.API_KEY,
	.api_secret = sensitive.API_SECRET,
	.http_client = &http_client
};
defer lastfm_client.http_client.*.deinit();
```