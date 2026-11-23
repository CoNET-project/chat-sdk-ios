import Foundation

/// Passcode rules.
/// ASCII digits, 8–12 long. Refused: all the same digit, a two-digit repeat, the COMMON list, a birthday-shaped date
/// (YYYYMMDD, MMDDYYYY or DDMMYYYY with a valid 1900–2099 date), and six consecutive digits that step up or down.
/// The reason codes are the ones of the vector file.
///
/// Only the rule check is here. The passcode itself is a String and cannot be wiped; the vault that uses it is not built yet.
public enum BeamioPasscodeRules {
	public static let minDigits = 8
	public static let maxDigits = 12

	/// The COMMON list (10 items), as digit bytes.
	public static let common: Set<[UInt8]> = Set([
		"00000000", "11111111", "12345678", "87654321", "12341234",
		"12121212", "20202020", "10101010", "13131313", "11223344",
	].map { Array($0.utf8) })

	/// nil when the passcode is acceptable; otherwise the reason code. The passcode is ASCII digit bytes, never a String.
	public static func refusal(_ d: [UInt8]) -> String? {
		guard d.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return "non_digit" }
		if d.count < minDigits { return "too_short" }
		if d.count > maxDigits { return "too_long" }
		if d.allSatisfy({ $0 == d[0] }) { return "all_same" }
		if d.enumerated().allSatisfy({ $0.element == d[$0.offset % 2] }) { return "repeat_pair" }
		if common.contains(d) { return "common" }
		if isBirthday(d) { return "birthday" }
		if hasSequence(d, run: 6) { return "sequence" }
		return nil
	}

	/// 8 digits that read as YYYYMMDD, MMDDYYYY or DDMMYYYY, with a valid date between 1900 and 2099.
	static func isBirthday(_ d: [UInt8]) -> Bool {
		guard d.count == 8 else { return false }
		func n(_ range: Range<Int>) -> Int { range.reduce(0) { $0 * 10 + Int(d[$1] - 48) } }
		let ymd = (year: n(0 ..< 4), month: n(4 ..< 6), day: n(6 ..< 8))
		let mdy = (year: n(4 ..< 8), month: n(0 ..< 2), day: n(2 ..< 4))
		let dmy = (year: n(4 ..< 8), month: n(2 ..< 4), day: n(0 ..< 2))
		return isValidDate(ymd.year, ymd.month, ymd.day)
			|| isValidDate(mdy.year, mdy.month, mdy.day)
			|| isValidDate(dmy.year, dmy.month, dmy.day)
	}

	static func isValidDate(_ year: Int, _ month: Int, _ day: Int) -> Bool {
		guard (1900 ... 2099).contains(year), (1 ... 12).contains(month) else { return false }
		let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
		let days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
		return (1 ... days[month - 1]).contains(day)
	}

	/// `run` consecutive digits, each one step from the previous in the same direction.
	static func hasSequence(_ d: [UInt8], run: Int) -> Bool {
		guard d.count >= run else { return false }
		for start in 0 ... (d.count - run) {
			let step = Int(d[start + 1]) - Int(d[start])
			guard step == 1 || step == -1 else { continue }
			if (1 ..< run - 1).allSatisfy({ i in Int(d[start + i + 1]) - Int(d[start + i]) == step }) {
				return true
			}
		}
		return false
	}
}
