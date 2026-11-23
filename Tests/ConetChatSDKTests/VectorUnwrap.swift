import XCTest

/// Unwraps a value read from a vector file. A vector file that is not set (an XCTSkip from the loader) propagates as a skip, not as a failure:
/// `XCTUnwrap` would turn the skip into a failure. A missing value in a set file is a failure.
func vectorUnwrap<T>(_ make: () throws -> T?, file: StaticString = #filePath, line: UInt = #line) throws -> T {
	guard let value = try make() else {
		XCTFail("the vector value is missing", file: file, line: line)
		throw XCTSkip("the vector value is missing")
	}
	return value
}
