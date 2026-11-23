import Foundation

/// Whether a call-control signal of a frame is handed to the call layer now. Pure.
enum CallSignalRule {
	static func shouldHandOver(isCallControl: Bool, delivered: Bool, observerRegistered: Bool) -> Bool {
		isCallControl && !delivered && observerRegistered
	}
}
