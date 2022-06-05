import Foundation
import CommonCrypto

public enum HOTP {
    
    static func hmac_sha1(key: Data, data: Data) -> Data {
        var result = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
        result.withUnsafeMutableBytes { resultBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), keyBytes.baseAddress, key.count, dataBytes.baseAddress, data.count, resultBytes.baseAddress)
                }
            }
        }
        return result
    }
    
    static func truncate(hash: Data) -> UInt32 {
        let offset = Int(hash[hash.count - 1] & 0x0f)
        let truncatedHash = hash[offset..<offset+4]
        var result: UInt32 = 0
        truncatedHash.withUnsafeBytes { bytes in
            let bytePointer = bytes.bindMemory(to: UInt8.self)
            result = (UInt32(bytePointer[0]) << 24) |
            (UInt32(bytePointer[1]) << 16) |
            (UInt32(bytePointer[2]) << 8)  |
            (UInt32(bytePointer[3]))
        }
        return result & 0x7fffffff
    }
    
    public static func generate(secret: Data, counter: UInt64, digits: Int = 6) -> String {
        var counter = counter.bigEndian
        let counterData = Data(bytes: &counter, count: MemoryLayout<UInt64>.size)
        let hash = hmac_sha1(key: secret, data: counterData)
        let truncatedHash = truncate(hash: hash)
        let hotp = truncatedHash % UInt32(pow(10, Float(digits)))
        return String(format: "%0*u", digits, hotp)
    }
}
