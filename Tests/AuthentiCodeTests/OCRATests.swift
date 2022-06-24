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
        // Test vector from RFC 6287 Appendix B.2
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
        // Test vector from RFC 6287 Appendix B.3
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
        // Test vector from RFC 6287 Appendix B.4
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
        // Test vector from RFC 6287 Appendix B.5
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
    
    // MARK: https://www.rfc-editor.org/rfc/rfc6287.html#appendix-C.1
    
    func testOCRA_C1_1() {
        let ocraSuite = "OCRA-1:HOTP-SHA1-6:QN08"
        let key = "3132333435363738393031323334353637383930"
        let counter = ""
        let password = ""
        let sessionInformation = ""
        let timeStamp = ""

        let questions = [
            "00000000",
            "11111111",
            "22222222",
            "33333333",
            "44444444",
            "55555555",
            "66666666",
            "77777777",
            "88888888",
            "99999999"
        ]

        let ocraValues = [
            "237653",
            "243178",
            "653583",
            "740991",
            "608993",
            "388898",
            "816933",
            "224598",
            "750600",
            "294470"
        ]

        for (index, expectedResponse) in ocraValues.enumerated() {
            let question = questions[index].hexFromBase10!
            let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
            XCTAssertEqual(ocra, expectedResponse, "Expected \(expectedResponse) but got \(String(describing: ocra))")
        }
    }
    
    func testOCRA_C1_2() {
        let ocraSuite = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1"
        let key = "3132333435363738393031323334353637383930313233343536373839303132"
        let password = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
        let sessionInformation = ""
        let timeStamp = ""
        
        let counters = [
            "00000000",
            "00000001",
            "00000002",
            "00000003",
            "00000004",
            "00000005",
            "00000006",
            "00000007",
            "00000008",
            "00000009"
        ]

        let questions = [
            "12345678",
            "12345678",
            "12345678",
            "12345678",
            "12345678",
            "12345678",
            "12345678",
            "12345678",
            "12345678",
            "12345678"
        ]

        let ocraValues = [
            "65347737",
            "86775851",
            "78192410",
            "71565254",
            "10104329",
            "65983500",
            "70069104",
            "91771096",
            "75011558",
            "08522129"
        ]

        for (index, expectedResponse) in ocraValues.enumerated() {
            let question = questions[index].hexFromBase10!
            let counter = counters[index]
            let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
            XCTAssertEqual(ocra, expectedResponse, "Expected \(expectedResponse) but got \(String(describing: ocra))")
        }
    }
    
    func testOCRA_C1_3() {
        let ocraSuite = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1"
        let key = "3132333435363738393031323334353637383930313233343536373839303132"
        let password = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
        let sessionInformation = ""
        let counter = ""
        let timeStamp = ""
        
        let questions = [
            "00000000",
            "11111111",
            "22222222",
            "33333333",
            "44444444"
        ]

        let ocraValues = [
            "83238735",
            "01501458",
            "17957585",
            "86776967",
            "86807031"
        ]

        for (index, expectedResponse) in ocraValues.enumerated() {
            let question = questions[index].hexFromBase10!
            let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
            XCTAssertEqual(ocra, expectedResponse, "Expected \(expectedResponse) but got \(String(describing: ocra))")
        }
    }

    func testOCRA_C1_4() {
        let ocraSuite = "OCRA-1:HOTP-SHA512-8:C-QN08"
        let key = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"
        let password = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
        let sessionInformation = ""
        let timeStamp = ""
        
        let counters = [
            "00000",
            "00001",
            "00002",
            "00003",
            "00004",
            "00005",
            "00006",
            "00007",
            "00008",
            "00009"
        ]

        let questions = [
            "00000000",
            "11111111",
            "22222222",
            "33333333",
            "44444444",
            "55555555",
            "66666666",
            "77777777",
            "88888888",
            "99999999"
        ]

        let ocraValues = [
            "07016083",
            "63947962",
            "70123924",
            "25341727",
            "33203315",
            "34205738",
            "44343969",
            "51946085",
            "20403879",
            "31409299"
        ]

        for (index, expectedResponse) in ocraValues.enumerated() {
            let question = questions[index].hexFromBase10!
            let counter = counters[index]
            let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
            XCTAssertEqual(ocra, expectedResponse, "Expected \(expectedResponse) but got \(String(describing: ocra))")
        }
    }

    func testOCRA_C1_5() {
        let ocraSuite = "OCRA-1:HOTP-SHA512-8:QN08-T1M"
        let key = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"
        let password = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
        let sessionInformation = ""
        let counter = ""
        
        let questions = [
            "00000000",
            "11111111",
            "22222222",
            "33333333",
            "44444444"
        ]

        let timestamps = [
            "132d0b6",
            "132d0b6",
            "132d0b6",
            "132d0b6",
            "132d0b6"
        ]

        let ocraValues = [
            "95209754",
            "55907591",
            "22048402",
            "24218844",
            "36209546"
        ]

        for (index, expectedResponse) in ocraValues.enumerated() {
            let question = questions[index].hexFromBase10!
            let timeStamp = timestamps[index]
            let ocra = OCRA.generate(ocraSuite: ocraSuite, key: key, counter: counter, question: question, password: password, sessionInformation: sessionInformation, timeStamp: timeStamp)
            XCTAssertEqual(ocra, expectedResponse, "Expected \(expectedResponse) but got \(String(describing: ocra))")
        }
    }
}

extension String {
    var hexFromBase10: String? {
        guard let base10Int = Int(self, radix: 10) else { return nil }
        return String(base10Int, radix: 16).uppercased()
    }
}
