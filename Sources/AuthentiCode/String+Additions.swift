import Foundation

extension String {
    var hexData: Data? {
        var data = Data(capacity: count / 2)
        var indexIsEven = true
        for i in self.indices {
            if indexIsEven {
                let byteString = self[i...self.index(after: i)]
                if var num = UInt8(byteString, radix: 16) {
                    data.append(&num, count: 1)
                } else {
                    return nil
                }
            }
            indexIsEven.toggle()
        }
        return data
    }
    
    var hexString: String? {
        let data = Data(utf8)
        let hexString = data.map{ String(format:"%02x", $0) }.joined()
        return hexString
    }
}
