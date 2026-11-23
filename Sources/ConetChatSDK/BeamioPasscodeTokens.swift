import Foundation

/// The passcode visual tokens (spec). The values are those of `interface/ui/passcode-tokens.v1.json`; a test
/// compares them with that file (PASSCODE_TOKENS). A build step generating these from the JSON is not in place yet.
public enum BeamioPasscodeTokens {
	public static let colors: [String: String] = [
		"bg": "#071126",
		"fg": "#FFFFFF",
		"fgMuted": "#FFFFFFBF",
		"accent": "#FFFFFF",
		"onAccent": "#071126",
		"danger": "#EF4444",
		"warn": "#FDE68A",
		"surface": "#FFFFFF1A",
		"border": "#FFFFFF26",
	]
	public static let titleSize: Double = 20
	public static let titleWeight: Int = 600
	public static let bodySize: Double = 14
	public static let captionSize: Double = 12
	public static let dotSize: Double = 14
	public static let dotGap: Double = 12
	public static let keyWidth: Double = 72
	public static let keyHeight: Double = 72
	public static let keyRadius: Double = 36
	public static let gridCols = 3
	public static let gridRows = 4
	public static let gridLabels: [String] = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "delete"]
	public static let cardRadius: Double = 24
	public static let shakeDurationMs = 320
	public static let shakeAmplitude: Double = 8
	public static let touchMinTarget: Double = 44
	public static let maxDigits = BeamioPasscodeRules.maxDigits
}
