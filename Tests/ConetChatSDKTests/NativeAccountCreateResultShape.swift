import Foundation

/// The page's `nativeAccountCreateResult` in its nested form (25.52Y.137 第 6 项): `{type, reqId, ok, result: {code, eoa?, cleanupPending?}}`.
/// The helpers read `result.code` and `result.eoa`; an event without `result` reads as nil.
func accountCreateResult(_ event: [String: Any]?) -> [String: Any]? {
	event?["result"] as? [String: Any]
}

func accountCreateCode(_ event: [String: Any]?) -> String? {
	accountCreateResult(event)?["code"] as? String
}

func accountCreateEoa(_ event: [String: Any]?) -> String? {
	accountCreateResult(event)?["eoa"] as? String
}
