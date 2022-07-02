import Foundation

extension String {
    /// HEX representation of given String's bytes.
    public var hexString: String? {
        let data = Data(utf8)
        let hexString = data.map{ String(format:"%02x", $0) }.joined()
        return hexString
    }
}
