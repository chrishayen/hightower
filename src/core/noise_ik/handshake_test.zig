const std = @import("std");
const handshake_ops = @import("handshake.zig");
const state_ops = @import("state.zig");
const crypto_ops = @import("crypto.zig");

const writeMessageA = handshake_ops.writeMessageA;
const readMessageA = handshake_ops.readMessageA;
const writeMessageB = handshake_ops.writeMessageB;
const readMessageB = handshake_ops.readMessageB;
const initHandshakeInitiator = state_ops.initHandshakeInitiator;
const initHandshakeResponder = state_ops.initHandshakeResponder;
const splitCiphers = state_ops.splitCiphers;
const generateKeyPair = crypto_ops.generateKeyPair;
const encryptWithAd = crypto_ops.encryptWithAd;
const decryptWithAd = crypto_ops.decryptWithAd;

test "full noise IK handshake succeeds" {
    const initiator_static = try generateKeyPair();
    const responder_static = try generateKeyPair();

    var initiator = initHandshakeInitiator(initiator_static, responder_static.public);
    var responder = initHandshakeResponder(responder_static);

    const initiator_payload = "hello from initiator";
    var msg_a: [1000]u8 = undefined;
    const msg_a_len = try writeMessageA(&initiator, initiator_payload, &msg_a);

    var received_payload_a: [1000]u8 = undefined;
    const payload_a_len = try readMessageA(&responder, msg_a[0..msg_a_len], &received_payload_a);

    try std.testing.expectEqualSlices(u8, initiator_payload, received_payload_a[0..payload_a_len]);

    const responder_payload = "hello from responder";
    var msg_b: [1000]u8 = undefined;
    const msg_b_len = try writeMessageB(&responder, responder_payload, &msg_b);

    var received_payload_b: [1000]u8 = undefined;
    const payload_b_len = try readMessageB(&initiator, msg_b[0..msg_b_len], &received_payload_b);

    try std.testing.expectEqualSlices(u8, responder_payload, received_payload_b[0..payload_b_len]);

    const initiator_ciphers = splitCiphers(&initiator);
    const responder_ciphers = splitCiphers(&responder);

    try std.testing.expectEqualSlices(u8, &initiator_ciphers[0].key, &responder_ciphers[0].key);
    try std.testing.expectEqualSlices(u8, &initiator_ciphers[1].key, &responder_ciphers[1].key);
}

test "write message A fails for responder" {
    const responder_key = try generateKeyPair();
    var state_obj = initHandshakeResponder(responder_key);

    var out: [1000]u8 = undefined;
    const result = writeMessageA(&state_obj, "", &out);

    try std.testing.expectError(error.InvalidRole, result);
}

test "write message B fails for initiator" {
    const initiator_key = try generateKeyPair();
    const responder_key = try generateKeyPair();
    var state_obj = initHandshakeInitiator(initiator_key, responder_key.public);

    var out: [1000]u8 = undefined;
    const result = writeMessageB(&state_obj, "", &out);

    try std.testing.expectError(error.InvalidRole, result);
}

test "read message A fails for initiator" {
    const initiator_key = try generateKeyPair();
    const responder_key = try generateKeyPair();
    var state_obj = initHandshakeInitiator(initiator_key, responder_key.public);

    var message = [_]u8{0} ** 100;
    var out: [1000]u8 = undefined;
    const result = readMessageA(&state_obj, &message, &out);

    try std.testing.expectError(error.InvalidRole, result);
}

test "read message B fails for responder" {
    const responder_key = try generateKeyPair();
    var state_obj = initHandshakeResponder(responder_key);

    var message = [_]u8{0} ** 100;
    var out: [1000]u8 = undefined;
    const result = readMessageB(&state_obj, &message, &out);

    try std.testing.expectError(error.InvalidRole, result);
}

test "read message A fails with too short message" {
    const responder_key = try generateKeyPair();
    var state_obj = initHandshakeResponder(responder_key);

    var message = [_]u8{0} ** 10;
    var out: [1000]u8 = undefined;
    const result = readMessageA(&state_obj, &message, &out);

    try std.testing.expectError(error.MessageTooShort, result);
}

test "read message B fails with too short message" {
    const initiator_static = try generateKeyPair();
    const responder_static = try generateKeyPair();

    var initiator = initHandshakeInitiator(initiator_static, responder_static.public);

    var msg_a: [1000]u8 = undefined;
    _ = try writeMessageA(&initiator, "", &msg_a);

    var message = [_]u8{0} ** 10;
    var out: [1000]u8 = undefined;
    const result = readMessageB(&initiator, &message, &out);

    try std.testing.expectError(error.MessageTooShort, result);
}

test "handshake rejects tampered message" {
    const initiator_static = try generateKeyPair();
    const responder_static = try generateKeyPair();

    var initiator = initHandshakeInitiator(initiator_static, responder_static.public);
    var responder = initHandshakeResponder(responder_static);

    const initiator_payload = "hello from initiator";
    var msg_a: [1000]u8 = undefined;
    const msg_a_len = try writeMessageA(&initiator, initiator_payload, &msg_a);

    msg_a[50] ^= 0xFF;

    var received_payload_a: [1000]u8 = undefined;
    const result = readMessageA(&responder, msg_a[0..msg_a_len], &received_payload_a);

    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "handshake with empty payloads succeeds" {
    const initiator_static = try generateKeyPair();
    const responder_static = try generateKeyPair();

    var initiator = initHandshakeInitiator(initiator_static, responder_static.public);
    var responder = initHandshakeResponder(responder_static);

    var msg_a: [1000]u8 = undefined;
    const msg_a_len = try writeMessageA(&initiator, "", &msg_a);

    var received_payload_a: [1000]u8 = undefined;
    const payload_a_len = try readMessageA(&responder, msg_a[0..msg_a_len], &received_payload_a);

    try std.testing.expectEqual(@as(usize, 0), payload_a_len);

    var msg_b: [1000]u8 = undefined;
    const msg_b_len = try writeMessageB(&responder, "", &msg_b);

    var received_payload_b: [1000]u8 = undefined;
    const payload_b_len = try readMessageB(&initiator, msg_b[0..msg_b_len], &received_payload_b);

    try std.testing.expectEqual(@as(usize, 0), payload_b_len);
}

test "handshake with large payloads succeeds" {
    const initiator_static = try generateKeyPair();
    const responder_static = try generateKeyPair();

    var initiator = initHandshakeInitiator(initiator_static, responder_static.public);
    var responder = initHandshakeResponder(responder_static);

    const initiator_payload = "x" ** 500;
    var msg_a: [2000]u8 = undefined;
    const msg_a_len = try writeMessageA(&initiator, initiator_payload, &msg_a);

    var received_payload_a: [2000]u8 = undefined;
    const payload_a_len = try readMessageA(&responder, msg_a[0..msg_a_len], &received_payload_a);

    try std.testing.expectEqualSlices(u8, initiator_payload, received_payload_a[0..payload_a_len]);

    const responder_payload = "y" ** 500;
    var msg_b: [2000]u8 = undefined;
    const msg_b_len = try writeMessageB(&responder, responder_payload, &msg_b);

    var received_payload_b: [2000]u8 = undefined;
    const payload_b_len = try readMessageB(&initiator, msg_b[0..msg_b_len], &received_payload_b);

    try std.testing.expectEqualSlices(u8, responder_payload, received_payload_b[0..payload_b_len]);
}

test "post-handshake transport encryption succeeds" {
    const initiator_static = try generateKeyPair();
    const responder_static = try generateKeyPair();

    var initiator = initHandshakeInitiator(initiator_static, responder_static.public);
    var responder = initHandshakeResponder(responder_static);

    const handshake_payload_a = "initiator handshake payload";
    var msg_a: [1000]u8 = undefined;
    const msg_a_len = try writeMessageA(&initiator, handshake_payload_a, &msg_a);

    var received_payload_a: [1000]u8 = undefined;
    const payload_a_len = try readMessageA(&responder, msg_a[0..msg_a_len], &received_payload_a);
    try std.testing.expectEqualSlices(u8, handshake_payload_a, received_payload_a[0..payload_a_len]);

    const handshake_payload_b = "responder handshake payload";
    var msg_b: [1000]u8 = undefined;
    const msg_b_len = try writeMessageB(&responder, handshake_payload_b, &msg_b);

    var received_payload_b: [1000]u8 = undefined;
    const payload_b_len = try readMessageB(&initiator, msg_b[0..msg_b_len], &received_payload_b);
    try std.testing.expectEqualSlices(u8, handshake_payload_b, received_payload_b[0..payload_b_len]);

    var initiator_ciphers = splitCiphers(&initiator);
    var responder_ciphers = splitCiphers(&responder);

    const initiator_message = "message from initiator";
    var encrypted_from_initiator: [1000]u8 = undefined;
    const encrypted_len = try encryptWithAd(&initiator_ciphers[0], "", initiator_message, &encrypted_from_initiator);
    initiator_ciphers[0].nonce += 1;

    var decrypted_at_responder: [1000]u8 = undefined;
    const decrypted_len = try decryptWithAd(&responder_ciphers[0], "", encrypted_from_initiator[0..encrypted_len], &decrypted_at_responder);
    responder_ciphers[0].nonce += 1;

    try std.testing.expectEqualSlices(u8, initiator_message, decrypted_at_responder[0..decrypted_len]);

    const responder_message = "message from responder";
    var encrypted_from_responder: [1000]u8 = undefined;
    const encrypted_len_resp = try encryptWithAd(&responder_ciphers[1], "", responder_message, &encrypted_from_responder);
    responder_ciphers[1].nonce += 1;

    var decrypted_at_initiator: [1000]u8 = undefined;
    const decrypted_len_init = try decryptWithAd(&initiator_ciphers[1], "", encrypted_from_responder[0..encrypted_len_resp], &decrypted_at_initiator);
    initiator_ciphers[1].nonce += 1;

    try std.testing.expectEqualSlices(u8, responder_message, decrypted_at_initiator[0..decrypted_len_init]);
}
