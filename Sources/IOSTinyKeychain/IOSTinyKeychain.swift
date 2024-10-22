// The Swift Programming Language
// https://docs.swift.org/swift-book
import Foundation
import Security

public protocol TinyKeychainProtocol {
    static func saveString(_ value: String, key: String) -> Bool
    static func saveData(_ value: Data, key: String) -> Bool
    static func readString(key: String) -> String?
    static func readData(key: String) -> Data?
}

public enum TinyKeychainService: TinyKeychainProtocol {

    public static func saveString(_ value: String, key: String) -> Bool {
        guard let data = value.data(using: .utf8)
        else { return false }
        return saveData(data, key: key)
    }

    public static func saveData(_ value: Data, key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: value
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    public static func readString(key: String) -> String? {
        guard let data = readData(key: key)
        else { return nil }

        return String(data: data, encoding: .utf8)
    }

    public static func readData(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess,
              let data = item as? Data
        else { return nil }

        return data
    }
}
