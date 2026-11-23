import Foundation

/// The transaction sequence of `pwaWalletSync` and `pwaEmptySignal` (25.52Y.163 r2.5.6 第 56 项; project ruling: the PWA's shellTxSeq is persisted,
/// monotonic and at least the millisecond clock, about 1.8e12). A valid seq is a JSON integer in 0 ... 2^53−1, held as Int64. Everything else is
/// `bad_request`: a decimal or exponent form (1.0, 1e0), a negative number, 2^53 or more, a string, a boolean, or no value.
enum BeamioPwaSeq {
	static let maxValue: Int64 = (1 << 53) - 1

	/// The seq of a decoded JSON value, or nil for `bad_request`. Decoding must keep the number form: a JSON `1.0` or `1e0` decodes as a
	/// floating-point NSNumber, which is refused here even though its value is an integer.
	static func parse(_ raw: Any?) -> Int64? {
		guard let number = raw as? NSNumber else { return nil }
		if CFGetTypeID(number) == CFBooleanGetTypeID() { return nil }
		if CFNumberIsFloatType(number) { return nil }
		let value = number.int64Value
		guard value >= 0, value <= maxValue else { return nil }
		return value
	}
}
