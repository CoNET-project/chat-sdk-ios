import Foundation

/// 1B: native asks PWA main thread to EIP-191 / EIP-712 sign; never holds EOA hex.
public enum BeamioConetChatSignBroker {
	public typealias WebEmit = (_ payload: [String: Any]) -> Void

	private static let lock = NSLock()
	private static var pending: [String: (Bool, String?, String?) -> Void] = [:]
	private static var emit: WebEmit?
	private static let defaultTimeout: TimeInterval = 30

	public static func setWebEmit(_ emit: WebEmit?) {
		lock.lock()
		self.emit = emit
		lock.unlock()
	}

	/// Request EIP-191 `personal_sign(message)` from PWA.
	public static func requestEip191(
		message: String,
		timeout: TimeInterval = 30,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		request(kind: "eip191", message: message, typedData: nil, timeout: timeout, completion: completion)
	}

	/// Request EIP-712 typed data signature from PWA.
	public static func requestEip712(
		typedData: [String: Any],
		timeout: TimeInterval = 30,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		request(kind: "eip712", message: nil, typedData: typedData, timeout: timeout, completion: completion)
	}

	public static func fulfill(fromWeb body: [String: Any]) {
		let reqId = String(body["reqId"] as? String ?? "")
		guard !reqId.isEmpty else { return }
		let ok = (body["ok"] as? Bool) ?? false
		let signature = body["signature"] as? String
		let error = body["error"] as? String
		lock.lock()
		let cb = pending.removeValue(forKey: reqId)
		lock.unlock()
		cb?(ok, signature, error)
	}

	public static func cancelAll(reason: String = "destroyed") {
		lock.lock()
		let all = pending
		pending.removeAll()
		lock.unlock()
		for (_, cb) in all {
			cb(false, nil, reason)
		}
	}

	private static func request(
		kind: String,
		message: String?,
		typedData: [String: Any]?,
		timeout: TimeInterval,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		let reqId = UUID().uuidString
		lock.lock()
		let emitFn = emit
		pending[reqId] = { ok, signature, error in
			if ok, let sig = signature, !sig.isEmpty {
				completion(.success(sig))
			} else {
				completion(.failure(NSError(
					domain: "BeamioConetChatSignBroker",
					code: -1,
					userInfo: [NSLocalizedDescriptionKey: error ?? "sign_failed"]
				)))
			}
		}
		lock.unlock()

		guard let emitFn else {
			fulfillLocal(reqId: reqId, ok: false, error: "no_web_emit")
			return
		}

		var payload: [String: Any] = [
			"action": "chatModuleSignRequest",
			"reqId": reqId,
			"kind": kind,
		]
		if let message { payload["message"] = message }
		if let typedData { payload["typedData"] = typedData }
		emitFn(payload)

		DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
			lock.lock()
			let still = pending.removeValue(forKey: reqId)
			lock.unlock()
			still?(false, nil, "sign_timeout")
		}
	}

	private static func fulfillLocal(reqId: String, ok: Bool, error: String?) {
		lock.lock()
		let cb = pending.removeValue(forKey: reqId)
		lock.unlock()
		cb?(ok, nil, error)
	}
}
