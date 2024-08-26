import Foundation
import CryptoKit
import mobile_sdk_rs

public class MockKeyManager: KeyManagerInterface {
    private var keys: [Key: P256.Signing.PrivateKey] = [:]

    public func reset() -> Bool {
        keys.removeAll()
        return true
    }

    public func keyExists(id: Key) -> Bool {
        return keys[id] != nil
    }

    public func generateSigningKey(id: Key) -> Bool {
        keys[id] = P256.Signing.PrivateKey()
        return true
    }

    public func getJwk(id: Key) throws -> String {
        guard let key = keys[id] else {
            throw NSError(domain: "MockKeyManager", code: 404, userInfo: [NSLocalizedDescriptionKey: "Key not found"])
        }

        let publicKey = key.publicKey
        let x = publicKey.x963Representation.dropFirst().prefix(32).base64EncodedString()
        let y = publicKey.x963Representation.dropFirst(33).base64EncodedString()

        let jwk = """
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "\(x)",
            "y": "\(y)"
        }
        """
        return jwk
    }

    public func signPayload(id: Key, payload: Data) throws -> Data {
        guard let key = keys[id] else {
            throw NSError(domain: "MockKeyManager", code: 404, userInfo: [NSLocalizedDescriptionKey: "Key not found"])
        }

        let signature = try key.signature(for: payload)
        return signature.rawRepresentation
    }

    public func generateEncryptionKey(id: Key) -> Bool {
        // For simplicity, we're using the same key type for both signing and encryption
        keys[id] = P256.Signing.PrivateKey()
        return true
    }

    public func encryptPayload(id: Key, payload: Data) throws -> EncryptedPayload {
        guard let _ = keys[id] else {
            throw NSError(domain: "MockKeyManager", code: 404, userInfo: [NSLocalizedDescriptionKey: "Key not found"])
        }

        // Simple XOR encryption with a random IV
        let iv = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let ciphertext = payload.enumerated().map { (index, byte) in
            return byte ^ iv[index % iv.count]
        }

        return EncryptedPayload(iv: iv, ciphertext: Data(ciphertext))
    }

    public func decryptPayload(id: Key, encryptedPayload: EncryptedPayload) throws -> Data {
        guard let _ = keys[id] else {
            throw NSError(domain: "MockKeyManager", code: 404, userInfo: [NSLocalizedDescriptionKey: "Key not found"])
        }

        let iv = encryptedPayload.iv()
        let ciphertext = encryptedPayload.ciphertext()

        // Simple XOR decryption
        let plaintext = ciphertext.enumerated().map { (index, byte) in
            return byte ^ iv[index % iv.count]
        }

        return Data(plaintext)
    }
}

let mockKeyManager = MockKeyManager()
let keyId: Key = "testKey"

// Generate a key
_ = mockKeyManager.generateSigningKey(id: keyId)

// Sign a payload
let payload = "Hello, World!".data(using: .utf8)!
let signature = try? mockKeyManager.signPayload(id: keyId, payload: payload)

// Encrypt a payload
let encryptedPayload = try? mockKeyManager.encryptPayload(id: keyId, payload: payload)

// Decrypt a payload
if let encryptedPayload = encryptedPayload {
    let decryptedData = try? mockKeyManager.decryptPayload(id: keyId, encryptedPayload: encryptedPayload)

    if let decryptedData = decryptedData {
        // Assert the decrypted data is the same as the original payload
        assert(decryptedData == payload)
    }

}
