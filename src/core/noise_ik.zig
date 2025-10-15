// Re-export types
const types = @import("noise_ik/types.zig");
pub const key_len = types.key_len;
pub const mac_len = types.mac_len;
pub const hash_len = types.hash_len;
pub const StaticKey = types.StaticKey;
pub const EphemeralKey = types.EphemeralKey;
pub const CipherState = types.CipherState;
pub const SymmetricState = types.SymmetricState;
pub const HandshakeState = types.HandshakeState;

// Re-export crypto operations
const crypto = @import("noise_ik/crypto.zig");
pub const generateKeyPair = crypto.generateKeyPair;
pub const generateEphemeralKey = crypto.generateEphemeralKey;
pub const dh = crypto.dh;

// Re-export state operations
const state = @import("noise_ik/state.zig");
pub const initSymmetricState = state.initSymmetricState;
pub const initHandshakeInitiator = state.initHandshakeInitiator;
pub const initHandshakeResponder = state.initHandshakeResponder;
pub const splitCiphers = state.splitCiphers;

// Re-export handshake operations
const handshake = @import("noise_ik/handshake.zig");
pub const writeMessageA = handshake.writeMessageA;
pub const readMessageA = handshake.readMessageA;
pub const writeMessageB = handshake.writeMessageB;
pub const readMessageB = handshake.readMessageB;
