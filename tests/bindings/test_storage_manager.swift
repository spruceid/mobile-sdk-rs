import Foundation
import mobile_sdk_rs

// Mock storage manager implementation
public class MockStorageManager: StorageManagerInterface {
    private var storage: [Key: Value] = [:]

    public func add(key: Key, value: Value) throws {
        storage[key] = value
    }

    public func get(key: Key) throws -> Value? {
        return storage[key]
    }

    public func list() throws -> [Key] {
        return Array(storage.keys)
    }

    public func remove(key: Key) throws {
        storage.removeValue(forKey: key)
    }
}
