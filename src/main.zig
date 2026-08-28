const ADDR = "127.0.0.1";
const PORT = 1965;
const CERT_FILE = "./certs/cert.pem";
const KEY_FILE = "./certs/key.pem";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const alloc = init.arena.allocator();
    const dir = try std.Io.Dir.cwd().openDir(io, ".", .{});
    const rng_impl: std.Random.IoSource = .{ .io = io };

    var auth = try tls.config.CertKeyPair.fromFilePath(alloc, io, dir, CERT_FILE, KEY_FILE);
    defer auth.deinit(alloc);

    const addr = try net.IpAddress.parse(ADDR, PORT);
    var server = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });

    var buf: [1024 + 2]u8 = undefined;
    while (true) {
        const stream = try server.accept(io);
        defer stream.close(io);
        std.log.info("Connection from {}", .{stream.socket.address});

        var conn = tls.serverFromStream(io, stream, .{
            .auth = &auth,
            .now = std.Io.Clock.real.now(io),
            .rng = rng_impl.interface(),
            .strict_close_notify = true,
        }) catch |err| {
            std.log.err("TLS failed: {}", .{err});
            continue;
        };
        defer conn.close() catch |err| std.log.err("Error closing conn: {}", .{err});

        const read_len = try conn.read(&buf);
        const msg = buf[0..read_len];
        std.log.info("Received request: {s}", .{msg});
        _ = try conn.write("20 text/plain \r\n");
        _ = try conn.write("Hello gemini!");

        std.log.info("Closing connection to {}", .{stream.socket.address});
    }
}

const std = @import("std");
const net = std.Io.net;

const tls = @import("tls");
