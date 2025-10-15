//! Noise_IK handshake message protocol implementation.
//!
//! Implements the two-message Noise_IK handshake pattern:
//! - Message A (initiator -> responder): e, es, s, ss
//! - Message B (responder -> initiator): e, ee, se
//!
//! After both messages are exchanged, both parties derive matching
//! transport cipher states for secure bidirectional communication.

const std = @import("std");
const types = @import("types.zig");
const crypto_ops = @import("crypto.zig");
const state_ops = @import("state.zig");

const key_len = types.key_len;
const mac_len = types.mac_len;
const HandshakeState = types.HandshakeState;

/// Write first handshake message (initiator -> responder)
///
/// Message format: e, es, s, ss, payload
/// - e: ephemeral public key
/// - es: DH(e, remote_s)
/// - s: encrypted static public key
/// - ss: DH(s, remote_s)
/// - payload: encrypted payload data
///
/// Returns total bytes written to output buffer.
pub fn writeMessageA(
    state: *HandshakeState,
    payload: []const u8,
    out: []u8,
) !usize {
    if (!state.is_initiator) {
        return error.InvalidRole;
    }

    if (state.remote_static_key == null) {
        return error.MissingRemoteStaticKey;
    }

    const e = try crypto_ops.generateEphemeralKey();
    state.ephemeral_key = e;

    var offset: usize = 0;

    @memcpy(out[offset..][0..key_len], &e.public);
    state_ops.mixHash(&state.symmetric, &e.public);
    offset += key_len;

    const dh_es = try crypto_ops.dh(e.secret, state.remote_static_key.?);
    state_ops.mixKey(&state.symmetric, &dh_es);

    const encrypted_s_len = try state_ops.encryptAndHash(&state.symmetric, &state.static_key.public, out[offset..]);
    offset += encrypted_s_len;

    const dh_ss = try crypto_ops.dh(state.static_key.secret, state.remote_static_key.?);
    state_ops.mixKey(&state.symmetric, &dh_ss);

    const encrypted_payload_len = try state_ops.encryptAndHash(&state.symmetric, payload, out[offset..]);
    offset += encrypted_payload_len;

    return offset;
}

/// Read first handshake message (responder <- initiator)
///
/// Message format: e, es, s, ss, payload
/// Processes ephemeral key, performs DH operations, decrypts static key
/// and payload. Returns decrypted payload length.
pub fn readMessageA(
    state: *HandshakeState,
    message: []const u8,
    payload_out: []u8,
) !usize {
    if (state.is_initiator) {
        return error.InvalidRole;
    }

    var offset: usize = 0;

    if (message.len < key_len) {
        return error.MessageTooShort;
    }

    var remote_ephemeral: [key_len]u8 = undefined;
    @memcpy(&remote_ephemeral, message[offset..][0..key_len]);
    state.remote_ephemeral_key = remote_ephemeral;
    state_ops.mixHash(&state.symmetric, &remote_ephemeral);
    offset += key_len;

    const dh_es = try crypto_ops.dh(state.static_key.secret, remote_ephemeral);
    state_ops.mixKey(&state.symmetric, &dh_es);

    const encrypted_s_len = key_len + mac_len;
    if (message.len < offset + encrypted_s_len) {
        return error.MessageTooShort;
    }

    var remote_static: [key_len]u8 = undefined;
    _ = try state_ops.decryptAndHash(
        &state.symmetric,
        message[offset..][0..encrypted_s_len],
        &remote_static,
    );
    state.remote_static_key = remote_static;
    offset += encrypted_s_len;

    const dh_ss = try crypto_ops.dh(state.static_key.secret, remote_static);
    state_ops.mixKey(&state.symmetric, &dh_ss);

    const remaining = message[offset..];
    const payload_len = try state_ops.decryptAndHash(&state.symmetric, remaining, payload_out);

    return payload_len;
}

/// Write second handshake message (responder -> initiator)
///
/// Message format: e, ee, se, payload
/// - e: ephemeral public key
/// - ee: DH(e, remote_e)
/// - se: DH(s, remote_e)
/// - payload: encrypted payload data
///
/// Returns total bytes written to output buffer.
pub fn writeMessageB(
    state: *HandshakeState,
    payload: []const u8,
    out: []u8,
) !usize {
    if (state.is_initiator) {
        return error.InvalidRole;
    }

    if (state.remote_ephemeral_key == null or state.remote_static_key == null) {
        return error.MissingRemoteKeys;
    }

    const e = try crypto_ops.generateEphemeralKey();
    state.ephemeral_key = e;

    var offset: usize = 0;

    @memcpy(out[offset..][0..key_len], &e.public);
    state_ops.mixHash(&state.symmetric, &e.public);
    offset += key_len;

    const dh_ee = try crypto_ops.dh(e.secret, state.remote_ephemeral_key.?);
    state_ops.mixKey(&state.symmetric, &dh_ee);

    const dh_se = try crypto_ops.dh(state.static_key.secret, state.remote_ephemeral_key.?);
    state_ops.mixKey(&state.symmetric, &dh_se);

    const encrypted_payload_len = try state_ops.encryptAndHash(&state.symmetric, payload, out[offset..]);
    offset += encrypted_payload_len;

    return offset;
}

/// Read second handshake message (initiator <- responder)
///
/// Message format: e, ee, se, payload
/// Processes ephemeral key, performs DH operations, decrypts payload.
/// Returns decrypted payload length.
pub fn readMessageB(
    state: *HandshakeState,
    message: []const u8,
    payload_out: []u8,
) !usize {
    if (!state.is_initiator) {
        return error.InvalidRole;
    }

    if (state.ephemeral_key == null) {
        return error.MissingEphemeralKey;
    }

    var offset: usize = 0;

    if (message.len < key_len) {
        return error.MessageTooShort;
    }

    var remote_ephemeral: [key_len]u8 = undefined;
    @memcpy(&remote_ephemeral, message[offset..][0..key_len]);
    state.remote_ephemeral_key = remote_ephemeral;
    state_ops.mixHash(&state.symmetric, &remote_ephemeral);
    offset += key_len;

    const dh_ee = try crypto_ops.dh(state.ephemeral_key.?.secret, remote_ephemeral);
    state_ops.mixKey(&state.symmetric, &dh_ee);

    const dh_se = try crypto_ops.dh(state.ephemeral_key.?.secret, state.remote_static_key.?);
    state_ops.mixKey(&state.symmetric, &dh_se);

    const remaining = message[offset..];
    const payload_len = try state_ops.decryptAndHash(&state.symmetric, remaining, payload_out);

    return payload_len;
}
