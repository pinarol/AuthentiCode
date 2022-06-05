import XCTest
import AuthentiCode

final class HOTPTests: XCTestCase {

    let secret = "12345678901234567890".data(using: .utf8)!
    
    let expectedResults = [
        "755224",
        "287082",
        "359152",
        "969429",
        "338314",
        "254676",
        "287922",
        "162583",
        "399871",
        "520489"
    ]
    
    func testHOTP() {
        for i in 0..<expectedResults.count {
            let hotp = HOTP.generate(secret: secret, counter: UInt64(i))
            XCTAssertEqual(hotp, expectedResults[i], "HOTP value for counter \(i) is incorrect")
        }
    }
}
