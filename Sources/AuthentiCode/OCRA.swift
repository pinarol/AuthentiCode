import CryptoKit
import Foundation

public class OCRA {
    
    /// Generates an OCRA HOTP value for the given set of parameters.
    /// - Parameters:
    ///   - ocraSuite: the OCRA Suite.
    ///   - key: the shared secret, HEX encoded.
    ///   - counter: the counter that changes on a per use basis, HEX encoded.
    ///   - question: the challenge question, HEX encoded.
    ///   - password: a password that can be used, HEX encoded.
    ///   - sessionInformation: Static information that identifies the current session, Hex encoded.
    ///   - timeStamp: a value that reflects a time, HEX encoded.
    /// - Returns: A numeric String in base 10 that includes digits.
    static public func generate(ocraSuite: String,
                                key: String,
                                counter: String,
                                question: String,
                                password: String,
                                sessionInformation: String,
                                timeStamp: String
    ) -> String? {
        var codeDigits: Int = 0
        var crypto: String = ""
        var counterLength: Int = 0
        var questionLength: Int = 0
        var passwordLength: Int = 0
        var sessionInformationLength: Int = 0
        var timeStampLength: Int = 0
        
        // The OCRASuites components
        let ocraSuiteComponents = ocraSuite.components(separatedBy: ":")
        guard ocraSuiteComponents.count > 2 else {
            return nil
        }
        let cryptoFunction = ocraSuiteComponents[1]
        let dataInput = ocraSuiteComponents[2]
        
        if cryptoFunction.lowercased().contains("sha1") {
            crypto = "HmacSHA1"
        }
        if cryptoFunction.lowercased().contains("sha256") {
            crypto = "HmacSHA256"
        }
        if cryptoFunction.lowercased().contains("sha512") {
            crypto = "HmacSHA512"
        }
        
        // How many digits should we return
        if let dashIndex = cryptoFunction.lastIndex(of: "-") {
            let codeDigitsString = cryptoFunction[cryptoFunction.index(after: dashIndex)...]
            codeDigits = Int(codeDigitsString) ?? 0
        }
        
        var counter = counter
        // The size of the byte array message to be encrypted
        // Counter
        if dataInput.lowercased().hasPrefix("c") {
            // Fix the length of the HEX string
            while counter.count < 16 {
                counter = "0" + counter
            }
            counterLength = 8
        }
        
        var question = question
        // Question - always 128 bytes
        if dataInput.lowercased().hasPrefix("q") || dataInput.lowercased().contains("-q") {
            while question.count < 256 {
                question += "0"
            }
            questionLength = 128
        }
        
        var password = password
        
        // Password - sha1
        if dataInput.lowercased().contains("psha1") {
            while password.count < 40 {
                password = "0" + password
            }
            passwordLength = 20
        }
        
        // Password - sha256
        if dataInput.lowercased().contains("psha256") {
            while password.count < 64 {
                password = "0" + password
            }
            passwordLength = 32
        }
        
        // Password - sha512
        if dataInput.lowercased().contains("psha512") {
            while password.count < 128 {
                password = "0" + password
            }
            passwordLength = 64
        }
        
        var sessionInformation = sessionInformation
        // sessionInformation - s064
        if dataInput.lowercased().contains("s064") {
            while sessionInformation.count < 128 {
                sessionInformation = "0" + sessionInformation
            }
            sessionInformationLength = 64
        }
        
        // sessionInformation - s128
        if dataInput.lowercased().contains("s128") {
            while sessionInformation.count < 256 {
                sessionInformation = "0" + sessionInformation
            }
            sessionInformationLength = 128
        }
        
        // sessionInformation - s256
        if dataInput.lowercased().contains("s256") {
            while sessionInformation.count < 512 {
                sessionInformation = "0" + sessionInformation
            }
            sessionInformationLength = 256
        }
        
        // sessionInformation - s512
        if dataInput.lowercased().contains("s512") {
            while sessionInformation.count < 1024 {
                sessionInformation = "0" + sessionInformation
            }
            sessionInformationLength = 512
        }
        
        var timeStamp = timeStamp
        // TimeStamp
        if dataInput.lowercased().hasPrefix("t") || dataInput.lowercased().contains("-t") {
            while timeStamp.count < 16 {
                timeStamp = "0" + timeStamp
            }
            timeStampLength = 8
        }
        
        let mutableData = NSMutableData()
        
        // Put the bytes of "ocraSuite" parameters into the message
        if let ocraSuiteData = ocraSuite.data(using: .utf8) {
            mutableData.append(ocraSuiteData)
        }
        
        var delimiter: UInt8 = 0x00
        mutableData.append(Data(bytes: &delimiter, count: 1))
        
        // Put the bytes of "Counter" to the message
        if counterLength > 0, let counterData = Data.fromHex(counter) {
            mutableData.append(counterData)
        }
        
        // Put the bytes of "question" to the message
        if questionLength > 0, let questionData = Data.fromHex(question) {
            mutableData.append(questionData)
        }
        
        // Put the bytes of "password" to the message
        if passwordLength > 0, let passwordData =  Data.fromHex(password) {
            mutableData.append(passwordData)
        }
        
        // Put the bytes of "sessionInformation" to the message
        if sessionInformationLength > 0, let sessionInfoData =  Data.fromHex(sessionInformation) {
            mutableData.append(sessionInfoData)
            
        }
        
        // Put the bytes of "time" to the message
        if timeStampLength > 0, let timeStampData = Data.fromHex(timeStamp) {
            mutableData.append(timeStampData)
        }
        
        guard let keyData = Data.fromHex(key) else {
            return nil
        }
        
        let hmacData = hmac(key: keyData, message: Data(referencing: mutableData), algorithm: getHMACAlgorithm(crypto: crypto))
        
        // Truncate and calculate the OTP
        return truncate(hmac: hmacData, digits: codeDigits)
    }
    
    private static func truncate(hmac: Data, digits: Int) -> String {
        let offset = Int(hmac[hmac.count - 1] & 0x0F)
        let truncatedHash = hmac.subdata(in: offset..<offset + 4)
        
        var number = UInt32(bigEndian: truncatedHash.withUnsafeBytes { $0.load(as: UInt32.self) }) & 0x7FFFFFFF
        number = number % UInt32(pow(10, Float(digits)))
        
        return String(format: "%0\(digits)d", number)
    }
    
    private static func getHMACAlgorithm(crypto: String) -> HMACAlgorithm {
        switch crypto {
        case "HmacSHA1":
            return .sha1
        case "HmacSHA256":
            return .sha256
        case "HmacSHA512":
            return .sha512
        default:
            return .sha256 // Default to SHA256
        }
    }
    
    static func hmac(key: Data, message: Data, algorithm: HMACAlgorithm) -> Data {
        let key = SymmetricKey(data: key)
        let mac: Data
        
        switch algorithm {
        case .sha1:
            mac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256:
            mac = Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512:
            mac = Data(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        
        return mac
    }
    
    private func truncate(hmac: Data) -> String {
        let offset = Int(hmac[hmac.count - 1] & 0x0F)
        let truncatedHash = hmac.subdata(in: offset..<offset+4)
        
        var number = UInt32(bigEndian: truncatedHash.withUnsafeBytes { $0.load(as: UInt32.self) }) & 0x7FFFFFFF
        number = number % 1000000
        
        return String(format: "%06d", number)
    }
}

enum HMACAlgorithm {
    case sha1, sha256, sha512
    
    var keyAlgorithm: Any.Type {
        switch self {
        case .sha1:
            return Insecure.SHA1.self
        case .sha256:
            return SHA256.self
        case .sha512:
            return SHA512.self
        }
    }
    
    var digestLength: Int {
        switch self {
        case .sha1:
            return Insecure.SHA1.byteCount
        case .sha256:
            return SHA256.byteCount
        case .sha512:
            return SHA512.byteCount
        }
    }
}
