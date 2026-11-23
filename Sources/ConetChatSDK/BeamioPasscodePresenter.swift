import Foundation

/// The shell's hook for the passcode overlay. `passcodeRun` asks the shell to present the native overlay for one
/// run. The shell calls `completion` exactly once with the result code. The overlay gets the digits from the user; nothing
/// is returned to the WebView except the code. `copy` holds the texts the PWA provides (not secret).
public enum BeamioPasscodePresenter {
	public static var present: ((BeamioPasscodeMode, String, [String: Any], @escaping (BeamioPasscodeRunResult) -> Void) -> Void)?
}
