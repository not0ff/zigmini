const ADDR = "127.0.0.1";
const PORT = 1965;
const CERT_FILE = "./certs/cert.pem";
const KEY_FILE = "./certs/key.pem";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const rng_impl: std.Random.IoSource = .{ .io = io };

    var auth = try tls.config.CertKeyPair.fromFilePath(gpa, io, Dir.cwd(), CERT_FILE, KEY_FILE);
    defer auth.deinit(gpa);

    const addr = try net.IpAddress.parse(ADDR, PORT);
    var server = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });

    while (true) {
        const stream = try server.accept(io);
        defer stream.close(io);

        var conn_arena: std.heap.ArenaAllocator = .init(gpa);
        defer conn_arena.deinit();
        const arena = conn_arena.allocator();

        var addr_buf: [512]u8 = undefined;
        var aw: Io.Writer = .fixed(&addr_buf);
        try stream.socket.address.format(&aw);
        const client_addr = aw.buffered();
        std.log.debug("Connection from {s}", .{client_addr});

        var conn = tls.serverFromStream(io, stream, .{
            .auth = &auth,
            .now = std.Io.Clock.real.now(io),
            .rng = rng_impl.interface(),
            .strict_close_notify = true,
        }) catch |err| {
            std.log.err("TLS failed: {}", .{err});
            continue;
        };
        defer conn.close() catch |err| std.log.err("Error closing conn from {s}: {}", .{ client_addr, err });

        var r_buf: [1024 + 2]u8 = undefined;
        var cr = conn.reader(&r_buf);
        const reader = &cr.interface;

        var w_buf: [1024 * 4]u8 = undefined;
        var cw = conn.writer(&w_buf);
        var writer = &cw.interface;
        defer writer.flush() catch {};

        handleClient(arena, io, reader, writer) catch |err| {
            std.log.err("Error handling {s}: {}", .{ client_addr, err });
        };
        std.log.debug("Closing connection to {s}", .{client_addr});
    }
}

fn handleClient(arena: Allocator, io: Io, reader: *Io.Reader, writer: *Io.Writer) !void {
    handleRequest(arena, io, reader, writer) catch |err| switch (err) {
        error.StreamTooLong => return writer.writeAll("59 Request too long \r\n"),
        error.MalformedRequest, error.MalformedPath, error.PathTraversal => return writer.writeAll("59 Malformed request \r\n"),
        error.InvalidPort => return writer.writeAll("53 Invalid port \r\n"),
        error.InvalidScheme => return writer.writeAll("53 Invalid scheme \r\n"),
        error.FileNotFound => return writer.writeAll("51 File not found \r\n"),
        error.EndOfStream, error.ReadFailed, error.WriteFailed => return,
        else => return err,
    };
}

fn handleRequest(arena: Allocator, io: Io, reader: *Io.Reader, writer: *Io.Writer) !void {
    const req = try reader.takeDelimiterInclusive('\n');
    if (!std.mem.endsWith(u8, req, "\r\n")) return error.MalformedRequest;

    const uri = std.Uri.parse(std.mem.trimEnd(u8, req, "\r\n")) catch return error.MalformedRequest;
    if (uri.fragment != null or uri.user != null or uri.password != null)
        return error.MalformedRequest;
    if (uri.port != null and uri.port.? != PORT)
        return error.InvalidPort;
    if (!std.mem.eql(u8, uri.scheme, "gemini"))
        return error.InvalidScheme;

    const path = try resolvePath(arena, uri);
    std.log.info("Client requested path \"{s}\"", .{path});

    if (path.len == 0) {
        try serveDirectory(io, writer, path);
    } else {
        try servePath(io, writer, path);
    }
}

fn servePath(io: Io, writer: *Io.Writer, path: []const u8) !void {
    var file = Dir.cwd().openFile(io, path, .{ .allow_directory = false, .follow_symlinks = false }) catch |err| switch (err) {
        error.IsDir => return try serveDirectory(io, writer, path),
        else => return err,
    };
    defer file.close(io);

    const ext = Dir.path.extension(path);
    const mime = mime_types.get(ext) orelse "application/octet-stream";
    try writer.print("20 {s} \r\n", .{mime});
    try writer.flush();

    var r_buf: [1024 * 4]u8 = undefined;
    var fr = file.reader(io, &r_buf);
    var reader = &fr.interface;

    _ = try reader.streamRemaining(writer);
}

fn serveDirectory(io: Io, writer: *Io.Writer, path: []const u8) !void {
    const dir_path = if (path.len == 0) "." else path;
    var dir = try Dir.cwd().openDir(io, dir_path, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(io);

    try writer.writeAll("20 text/gemini \r\n");
    try writer.flush();

    try writer.print("# Directory listing for \"{s}\": \r\n\r\n", .{dir_path});

    if (path.len != 0)
        try writer.print("=> gemini://{s}/{s} [Parent directory] \r\n", .{ ADDR, Dir.path.dirname(path) orelse "" });

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (path.len == 0) {
            try writer.print("=> gemini://{s}/{s} {s} \r\n", .{ ADDR, entry.name, entry.name });
        } else {
            try writer.print("=> gemini://{s}/{s}/{s} {s} \r\n", .{ ADDR, path, entry.name, entry.name });
        }
    }
}

fn resolvePath(arena: Allocator, uri: std.Uri) ![]const u8 {
    const raw = try uri.path.toRawMaybeAlloc(arena);
    const decoded = std.mem.trim(u8, raw, "/");
    return sanitizePath(arena, decoded);
}

fn sanitizePath(arena: Allocator, decoded: []const u8) ![]const u8 {
    if (std.mem.indexOfScalar(u8, decoded, 0) != null)
        return error.MalformedPath;

    var segments: std.ArrayList([]const u8) = .empty;
    defer segments.deinit(arena);

    var it = std.mem.tokenizeAny(u8, decoded, "/");
    while (it.next()) |segment| {
        if (std.mem.eql(u8, segment, ".")) continue;
        if (std.mem.eql(u8, segment, "..")) return error.PathTraversal;
        if (std.mem.indexOfScalar(u8, segment, ':') != null)
            return error.MalformedPath;
        try segments.append(arena, segment);
    }
    return Dir.path.join(arena, segments.items);
}

const mime_types: std.StaticStringMap([]const u8) = .initComptime(.{
    .{ ".avif", "image/avif" },
    .{ ".bmp", "image/bmp" },
    .{ ".gif", "image/gif" },
    .{ ".jpeg", "image/jpeg" },
    .{ ".jpg", "image/jpeg" },
    .{ ".md", "text/markdown" },
    .{ ".mp3", "audio/mpeg" },
    .{ ".png", "image/png" },
    .{ ".pdf", "application/pdf" },
    .{ ".txt", "text/plain" },
    .{ ".wav", "audio/wav" },
    .{ ".gmi", "text/gemini" },
});

const std = @import("std");
const net = std.Io.net;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;

const tls = @import("tls");
