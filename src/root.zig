const std = @import("std");
const testing = std.testing;
const http = std.http;
const sensitive = @import("./sensitive.zig");

const InvocationOptions = struct {
    hash_token: bool = false,
    sign_request: bool = false,
    http_method: http.Method = .GET,
    as_json: bool = true,
    response_body: ?*std.ArrayList(u8),
    logging: bool = false
};

const InvocationResult = struct {
    status: http.Status
};

const Session = struct {
    name: []const u8,
    key: [32]u8,
    subscriber: u1,

    pub fn subscribed(self: Session) bool { return self.subscriber == @as(u1, 1); }
};

const Scrobble = struct {
    artist: []const u8,
    track: []const u8,
    timestamp: u32,
    album: ?[]const u8,
    chosenByUser: bool = false,
    trackNumber: ?u8,
    duration: ?u32
};

const InvocationError = error {
    MissingToken,
    UnsupportedHTTPMethod,
};

const HttpError = error {
    NotOk
};

const QueryParameters = std.StringHashMap([]const u8);

/// A client for interacting with Last.fm's API.
const LastFMClient = struct {
    ally: std.mem.Allocator,
    api_key: *const [32:0]u8,
    api_secret: *const [32:0]u8,
    base_url: []const u8 = "https://ws.audioscrobbler.com/2.0/",
    base_url_login: []const u8 = "http://www.last.fm/api/auth/",
    http_client: *http.Client,
    session: ?Session = null,

    /// Invoke a Last.fm method directly. This is used internally by the other
    /// methods in this struct, which you should use instead if possible.
    pub fn invoke(self: LastFMClient, method: []const u8, params: QueryParameters, options: InvocationOptions) !InvocationResult {
        if (options.logging) {
            std.debug.print("Invoking LastFM {s}\n", .{method});
        }

        // Add necessary keys to the existing query parameters
        var my_params = params;
        defer my_params.deinit();
        try my_params.put("api_key", self.api_key);
        try my_params.put("method", method);

        // Optionally hash the given token
        if (options.hash_token) { 
            // Check if we have a token to hash
            if (!my_params.contains("token")) {
                return InvocationError.MissingToken;
            }

            if (options.logging) {
                std.debug.print("  token = {s}\n", .{my_params.get("token").?});
            }

            // Pass the token through MD5
            const md5_str = try md5(my_params.get("token").?);
            try my_params.put("token", &md5_str);

            if (options.logging) {
                std.debug.print("  MD5(token) = {s}\n", .{&md5_str});
            }
        }

        // Optionally sign the request
        if (options.sign_request) {
            const signature = try self.generateSignature(&params);
            try my_params.put("api_sig", &signature);

            if (options.logging) {
                std.debug.print("  signature = {s}\n", .{&signature});
            }
        }

        // Optionally add format=json
        if (options.as_json) {
            try my_params.put("format", "json");
        }

        // Perform the HTTP request
        const response_storage: http.Client.FetchOptions.ResponseStorage = if (options.response_body != null) .{ .dynamic = options.response_body.? } else .{ .ignore = {} };
        var response: http.Client.FetchResult = undefined;
        switch(options.http_method) {
            .GET => {
                // Build the URL
                var url_builder = try paramsToQueryString(my_params, self.ally);
                errdefer url_builder.deinit();
                try url_builder.insert(0, '?');
                try url_builder.insertSlice(0, self.base_url);
                const url = try url_builder.toOwnedSlice();
                defer self.ally.free(url);
                if (options.logging) {
                    std.debug.print("  url = {s}\n", .{ url });
                }

                // Fetch
                response = try self.http_client.fetch(.{
                    .method = .GET,
                    .response_storage = response_storage,
                    .location = .{
                        .url = url
                    },
                });
            },
            .POST => {
                // Create payload
                var payload_builder = try generatePostBody(&my_params, self.ally);
                const payload = try payload_builder.toOwnedSlice();
                defer self.ally.free(payload);

                // Fetch
                response = try self.http_client.fetch(.{
                    .method = .POST,
                    .response_storage = response_storage,
                    .payload = payload,
                    .location = .{
                        .url = self.base_url
                    },
                });
            },
            else => return InvocationError.UnsupportedHTTPMethod,
        }

        // Return relevant data
        if (options.logging) {
            std.debug.print("  ==> status {d}\n", .{response.status});
        }

        return .{
            .status = response.status
        };
    }

    /// Generate an API signature given the query parameters.
    /// The result is pre-hashed with MD5.
    pub fn generateSignature(self: LastFMClient, params: *const QueryParameters) ![32]u8 {
        // Get a list of all the keys
        var sorted_keys_list = std.ArrayList([]const u8).init(self.ally);
        errdefer sorted_keys_list.deinit();

        var iter = params.*.keyIterator();
        while (iter.next()) |key| {
            // Append the key to the list
            const key_str: []const u8 = key.*;
            try sorted_keys_list.append(key_str);
        }

        // Sort them
        const sorted_keys = try sorted_keys_list.toOwnedSlice();
        defer self.ally.free(sorted_keys);
        std.mem.sort([]const u8, sorted_keys, {}, stringCompare);

        // Start building the signature string
        var sig = std.ArrayList(u8).init(self.ally);
        errdefer sig.deinit();
        for (sorted_keys) |key| {
            // Get the value for the key
            const value = params.*.get(key).?;

            // Append the key and value to the signature string
            try sig.appendSlice(key);
            try sig.appendSlice(value);
        }

        // Append the api_secret to the end of the string
        try sig.appendSlice(self.api_secret);

        // Return the MD5 hash of the signature string
        const sig_str = try sig.toOwnedSlice();
        defer self.ally.free(sig_str);
        std.debug.print("  raw sig = {s}\n", .{ sig_str });
        const md5_str = try md5(sig_str);
        return md5_str;
    }

    /// Get an authorization token to be exchanged for a session key.
    pub fn getToken(self: LastFMClient) ![32]u8 {
        // Call the API endpoint
        var params = QueryParameters.init(self.ally);
        defer params.deinit();

        var res_body = std.ArrayList(u8).init(self.ally);
        errdefer res_body.deinit();
        const res = try self.invoke("auth.getToken", params, .{
            .response_body = &res_body,
            .as_json = true,
        });
        if (res.status != http.Status.ok) {
            return HttpError.NotOk;
        }

        // Extract token from response body
        const res_body_slice = try res_body.toOwnedSlice();
        defer self.ally.free(res_body_slice);
        const TokenResponse = struct { token: []const u8 };
        const parsed = try std.json.parseFromSlice(TokenResponse, self.ally, res_body_slice, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        // Return the token
        const token = try self.ally.dupe(u8, parsed.value.token);
        defer self.ally.free(token);
        return token[0..32].*;
    }

    /// Get a link for the user to visit in order to authorize the given token to be exchanged for a session.
    /// Make sure to free when finished!
    pub fn getLoginUrl(self: LastFMClient, token: [32]u8) ![]const u8 {
        // Build the login URL
        // TODO this should probably use a format string?
        var url = std.ArrayList(u8).init(self.ally);
        errdefer url.deinit();
        try url.appendSlice(self.base_url_login);
        try url.appendSlice("?api_key=");
        try url.appendSlice(self.api_key);
        try url.appendSlice("&token=");
        try url.appendSlice(&token);

        // Return it
        const url_slice = try url.toOwnedSlice();
        return url_slice;
    }

    /// Exchange the given token for a session to use for authenticated calls. Feed this result into `useSession()`.
    pub fn getSession(self: LastFMClient, token: [32]u8) !Session {
        // Call the API endpoint
        var params = QueryParameters.init(self.ally);
        // defer params.deinit();
        try params.put("token", &token);

        var res_body = std.ArrayList(u8).init(self.ally);
        errdefer res_body.deinit();
        const res = try self.invoke("auth.getSession", params, .{
            .response_body = &res_body,
            .as_json = true,
            .logging = true,
            // .hash_token = true,
            .sign_request = true
        });

        // Extract session from response body
        const res_body_slice = try res_body.toOwnedSlice();
        defer self.ally.free(res_body_slice);

        // Stop if the response errored
        std.debug.print("{s}\n", .{ res_body_slice });
        if (res.status != http.Status.ok) {
            return HttpError.NotOk;
        }

        const SessionResponse = struct {
            session: Session,
        };

        const parsed: std.json.Parsed(SessionResponse) = try std.json.parseFromSlice(SessionResponse, self.ally, res_body_slice, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();

        // Return the session object
        const session: Session = parsed.value.session;
        return session;
    }

    /// Store the given session object. Any further authenticated calls will use this session.
    pub fn useSession(self: *LastFMClient, session: Session) void {
        self.session = session;
    }

    /// Returns `true` if there is an active session, `false` otherwise.
    pub fn authenticated(self: *LastFMClient) bool {
        return self.session != null;
    }

    // fn addScrobbleToParams(params: *QueryParameters, scrobble: Scrobble, index: ?usize) !void {
    //     index = index orelse 0;
        
    // }

    // /// Scrobble a single track. Returns `true` if successful, `false` otherwise.
    // pub fn scrobble(self: *LastFMClient) bool {

    // }
};

/// Utility function to hash a string using MD5, returned as a string.
/// 
/// ```zig
/// const md5_str = try md5("my_value");
/// ```
fn md5(data: []const u8) ![32]u8 {
    // Pass the data through MD5
    var hashed: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(data, &hashed, .{});

    // Convert the MD5 hash to a string
    var md5_str = [_]u8{ ' ' } ** 32;
    for (hashed, 0..) |byte, i| {
        var byte_str: [2]u8 = undefined;
        _ = try std.fmt.bufPrint(&byte_str, "{x:0>2}", .{byte});
        md5_str[i * 2] = byte_str[0];
        md5_str[i * 2 + 1] = byte_str[1];
    }

    // Return the result
    return md5_str;
}

/// Utility function to build a query string from a QueryParameters instance. If there are
/// no parameters, an empty string is returned. Must be freed by the caller!
/// 
/// ```zig
/// const query_str = try paramsToQueryString(params, ally);
/// defer query_str.deinit();
/// ```
fn paramsToQueryString(params: QueryParameters, ally: std.mem.Allocator) !std.ArrayList(u8) {
    // Initialize a variable-length string to store our params in
    var query_str = std.ArrayList(u8).init(ally);

    // If there's no parameters, return empty string
    if (params.count() == 0) {
        return query_str;
    }

    // Loop through each of the keys in the params
    var iter = params.keyIterator();
    while (iter.next()) |key| : (try query_str.append('&')) {
        const val = params.get(key.*).?;
        const buf = try ally.alloc(u8, key.*.len + val.len + 1);
        defer ally.free(buf);
        _ = try std.fmt.bufPrint(buf, "{s}={s}", .{ key.*, val });
        try query_str.appendSlice(buf);
    }

    // Return the string
    return query_str;
}

/// Utility function to compare two strings based on ASCII order.
/// To be used with `std.mem.sort()`.
fn stringCompare(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.ascii.orderIgnoreCase(lhs, rhs).compare(.lt);
}

/// Generate a post body given the parameters to be used by POST endpoints
fn generatePostBody(params: *const QueryParameters, ally: std.mem.Allocator) !std.ArrayList(u8) {
    // Get a list of all the keys
    var sorted_keys_list = std.ArrayList([]const u8).init(ally);
    errdefer sorted_keys_list.deinit();

    var iter = params.*.keyIterator();
    while (iter.next()) |key| {
        // Append the key to the list
        const key_str: []const u8 = key.*;
        try sorted_keys_list.append(key_str);
    }

    // Sort them
    const sorted_keys = try sorted_keys_list.toOwnedSlice();
    defer ally.free(sorted_keys);
    std.mem.sort([]const u8, sorted_keys, {}, stringCompare);

    // Start building the post body
    var body = std.ArrayList(u8).init(ally);
    errdefer body.deinit();
    for (sorted_keys) |key| {
        // Get the value for the key
        const value = params.*.get(key).?;

        // Append the key and value to the body
        try body.appendSlice(key);
        try body.append('=');
        try body.appendSlice(value);
        try body.append('&');
    }

    // Return the body
    return body;
}

test "invoke GET" {
    // Create a LastFMClient
    const ally = testing.allocator;

    var http_client = http.Client{
        .allocator = ally
    };
    
    const lastfm_client = LastFMClient{
        .api_key = sensitive.API_KEY,
        .api_secret = sensitive.API_SECRET,
        .http_client = &http_client,
        .ally = ally
    };
    defer lastfm_client.http_client.*.deinit();

    // Attempt to invoke track.getInfo
    var params = QueryParameters.init(ally);
    try params.put("track", "believe");
    try params.put("artist", "cher");

    var res_body = std.ArrayList(u8).init(ally);
    errdefer res_body.deinit();
    const result = try lastfm_client.invoke("track.getInfo", params, .{ .logging = true, .response_body = &res_body });
    std.debug.print("Returned with status {d}\n", .{ result.status });
    try testing.expect(result.status == http.Status.ok);

    // Grab the body from the response
    const res_body_slice = try res_body.toOwnedSlice();
    defer ally.free(res_body_slice);
    std.debug.print("Response body:\n{s}\n", .{ res_body_slice });
}

test "get an authorization token" {
    // Create a LastFMClient
    const ally = testing.allocator;

    var http_client = http.Client{
        .allocator = ally
    };
    
    const lastfm_client = LastFMClient{
        .api_key = sensitive.API_KEY,
        .api_secret = sensitive.API_SECRET,
        .http_client = &http_client,
        .ally = ally
    };
    defer lastfm_client.http_client.*.deinit();

    // Ask for a token
    const token = try lastfm_client.getToken();
    try testing.expect(token.len > 3);
    std.debug.print("Auth token: {s}\n", .{ token });
}

test "get a session from an authorization token" {
    // Create a LastFMClient
    const ally = testing.allocator;

    var http_client = http.Client{
        .allocator = ally
    };
    
    const lastfm_client = LastFMClient{
        .api_key = sensitive.API_KEY,
        .api_secret = sensitive.API_SECRET,
        .http_client = &http_client,
        .ally = ally
    };
    defer lastfm_client.http_client.*.deinit();

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
}

test "generate a valid API signature" {
    // Create a LastFMClient
    const ally = testing.allocator;

    var http_client = http.Client{
        .allocator = ally
    };
    
    const lastfm_client = LastFMClient{
        .api_key = "a" ** 32,
        .api_secret = "a" ** 32,
        .http_client = &http_client,
        .ally = ally
    };
    defer lastfm_client.http_client.*.deinit();

    // Put some params in at will
    var params = QueryParameters.init(ally);
    defer params.deinit();
    try params.put("c", "3");
    try params.put("a", "1");
    try params.put("bb", "22");

    // Generate a signature
    const generated_sig = try lastfm_client.generateSignature(&params);
    const expected_sig = try md5("a1bb22c3" ++ ("a" ** 32));
    try testing.expect(std.mem.eql(u8, &generated_sig, &expected_sig));
}

// test "scrobble a single track" {
//     // Create a LastFMClient
//     const ally = testing.allocator;

//     var http_client = http.Client{
//         .allocator = ally
//     };
    
//     var lastfm_client = LastFMClient{
//         .api_key = "a" ** 32,
//         .api_secret = "a" ** 32,
//         .http_client = &http_client,
//         .ally = ally
//     };
//     defer lastfm_client.http_client.*.deinit();

//     // Ask for a token
//     const token = try lastfm_client.getToken();

//     // Prompt user to authorize the token
//     const login_url = try lastfm_client.getLoginUrl(token);
//     defer ally.free(login_url);
//     std.debug.print("Please visit the following URL to allow this application to access your Last.fm account.\n{s}\n\nPress enter when you are finished.\n", .{ login_url });
//     const stdin = std.io.getStdIn().reader();
//     try stdin.skipUntilDelimiterOrEof('\n');

//     // Exchange the token for a session
//     const session = try lastfm_client.getSession(token);
//     lastfm_client.useSession(session);

//     // Scrobble a dummy track
    
// }