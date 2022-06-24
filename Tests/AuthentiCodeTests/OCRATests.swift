import XCTest
import CryptoKit
@testable import AuthentiCode

// Test vectors from RFC 6287
class OCRATests: XCTestCase {
    
    func testOCRAExample1() {
        // Test vector from RFC 6287 Appendix B.1
        let ocraSuite = "OCRA-1:HOTP-SHA512-8:QA10-T1M"
        let key = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"
        let counter = ""
        let question = "SIG1000000".hexString!
        let password = ""
        let sessionInformation = ""
        let timeStamp = "132D0B6"
        
        let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
        
        let expectedResponse = "77537423"
        XCTAssertEqual(ocra, expectedResponse, "Expected \(expectedResponse) but got \(String(describing: ocra))")
    }
    
    func testOCRAExample2() {
        let ocraSuite = "OCRA-1:HOTP-SHA256-8:QA08"
        let key = "3132333435363738393031323334353637383930313233343536373839303132"
        let counter = ""
        let question = "SIG10000".hexString!
        let password = ""
        let sessionInformation = ""
        let timeStamp = "132D0B6"
        
        let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
        let expectedResponse = "53095496"
        XCTAssertEqual(ocra, expectedResponse, "Expected \(expectedResponse) but got \(String(describing: ocra))")
    }
    
    func testOCRAExample3() {
        let ocraSuite = "OCRA-1:HOTP-SHA512-8:QN08-T1M"
        let key = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"
        let counter = ""
        let question = "00000000"
        let password = ""
        let sessionInformation = ""
        let timeStamp = "132D0B6"
        
        let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
        let expectedResponse = "95209754"
        XCTAssertEqual(ocra, expectedResponse, "Expected \(expectedResponse) but got \(String(describing: ocra))")
    }
    
    func testOCRAExample4() {
        let ocraSuite = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1"
        let key = "3132333435363738393031323334353637383930313233343536373839303132"
        let counter = ""
        let question = "00000000"
        let password = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
        let sessionInformation = ""
        let timeStamp = ""
        
        let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
        let expectedResponse = "83238735"
        XCTAssertEqual(ocra, expectedResponse, "Expected \(expectedResponse) but got \(String(describing: ocra))")
    }
    
    func testOCRAExample5() {
        let ocraSuite = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1"
        let key = "3132333435363738393031323334353637383930313233343536373839303132"
        let counter = "0"
        let question = "BC614E"
        let password = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
        let sessionInformation = ""
        let timeStamp = ""
        
        let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
        let expectedResponse = "65347737"
        XCTAssertEqual(ocra, expectedResponse, "Expected \(expectedResponse) but got \(String(describing: ocra))")
    }
}
