import Foundation

extension Data {
    
    static func fromHex(_ string: String) -> Data? {
        var data = Data(capacity: string.count / 2)
        var indexIsEven = true
        for i in string.indices {
            if indexIsEven {
                let byteString = string[i...string.index(after: i)]
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
}
