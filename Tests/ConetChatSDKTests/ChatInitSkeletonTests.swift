import XCTest
@testable import ConetChatSDK

/// The `chatInit` skeleton (draft r2.5.20 v7): the pure contract only. Nothing here is on the bridge: `chatInit` is not a known command, and the
/// skeleton reads no store and writes nothing.
final class ChatInitSkeletonTests: XCTestCase {
	private let closedSet: Set<String> = ["ready", "pending_confirm", "registering", "restore_failed", "error"]

	func testTheExternalStatusSetIsTheClosedSetOfTheDraft() {
		let raws = Set([
			BeamioChatInitSkeleton.Status.ready, .pendingConfirm, .registering, .restoreFailed, .error,
		].map(\.rawValue))
		XCTAssertEqual(raws, closedSet)
	}

	func testEveryInternalStateMapsIntoTheClosedSet() {
		let internals: [BeamioChatInitSkeleton.Internal] = [
			.unknown, .retryReady, .undetermined, .normalEvaluation, .writing, .ready, .registering, .restoreFailed, .error,
		]
		for state in internals {
			XCTAssertTrue(closedSet.contains(BeamioChatInitSkeleton.status(of: state).rawValue), "\(state)")
		}
	}

	func testTheWaitStatesAreAllPendingConfirmAndRetryReadyIsNeverRegistering() {
		for state in [BeamioChatInitSkeleton.Internal.unknown, .retryReady, .undetermined, .normalEvaluation, .writing] {
			XCTAssertEqual(BeamioChatInitSkeleton.status(of: state), .pendingConfirm, "\(state)")
		}
		XCTAssertNotEqual(BeamioChatInitSkeleton.status(of: .retryReady), .registering)
		XCTAssertEqual(BeamioChatInitSkeleton.status(of: .registering), .registering)
	}

	func testG0AndG1AnswerPendingConfirmAndOnlyG2RunsTheFlow() {
		XCTAssertEqual(BeamioChatInitSkeleton.gateStatus(.g0), .pendingConfirm)
		XCTAssertEqual(BeamioChatInitSkeleton.gateStatus(.g1), .pendingConfirm)
		XCTAssertNil(BeamioChatInitSkeleton.gateStatus(.g2))
	}

	func testTheWorkspaceDefaultsToDefaultAndANonStringIsRefused() {
		XCTAssertEqual(BeamioChatInitSkeleton.workspace([:]), "default")
		XCTAssertEqual(BeamioChatInitSkeleton.workspace(["workspace": "work"]), "work")
		XCTAssertNil(BeamioChatInitSkeleton.workspace(["workspace": 3]))
	}

	func testTheAnswerCarriesOnlyWhitelistedFieldsAndNoForbiddenName() {
		let answer = BeamioChatInitSkeleton.answer(reqId: 7, status: .ready, eoa: "0xABCDef0000000000000000000000000000000001", keyId: "K1",
		                                           publicKeyArmored: "PUB", registration: .confirmed, code: nil)
		XCTAssertTrue(BeamioChatInitSkeleton.isPublic(answer))
		XCTAssertEqual(answer["eoa"] as? String, "0xabcdef0000000000000000000000000000000001", "eoa is lower case")
		XCTAssertNil(answer["code"], "no code on ready")
		let leaked: [String: Any] = answer.merging(["privateKeyArmor": "x"]) { old, _ in old }
		XCTAssertFalse(BeamioChatInitSkeleton.isPublic(leaked))
	}

	func testTheCodeAppearsOnlyForErrorAndRestoreFailed() {
		let pending = BeamioChatInitSkeleton.answer(reqId: 1, status: .pendingConfirm, eoa: nil, keyId: nil, publicKeyArmored: nil,
		                                            registration: .none, code: "x")
		XCTAssertNil(pending["code"])
		let failed = BeamioChatInitSkeleton.answer(reqId: 1, status: .restoreFailed, eoa: nil, keyId: nil, publicKeyArmored: nil,
		                                           registration: .none, code: "pgp_locked")
		XCTAssertEqual(failed["code"] as? String, "pgp_locked")
		let error = BeamioChatInitSkeleton.answer(reqId: 1, status: .error, eoa: nil, keyId: nil, publicKeyArmored: nil,
		                                          registration: .none, code: "bad_request")
		XCTAssertEqual(error["code"] as? String, "bad_request")
	}

	func testChatInitIsNotRegisteredToTheBridge() {
		XCTAssertFalse(BeamioConetChatModule.knownBridgeCommand("chatInit"))
		XCTAssertFalse(BeamioConetChatModule.knownBridgeCommand("chatInitResult"))
	}
}
