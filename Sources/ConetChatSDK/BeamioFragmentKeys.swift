import Foundation

/// W4 fragment keys. One key per fragment: `fragKey(seq, prevCid) = HKDF(R_proto, "frag|" + seq + "|" + prevCid, 32)`.
/// The derivation is the only place the info string is built. The history store (write and materialize) and the sync read point call `key`,
/// so the vectors D-04 and D-05 test the production derivation directly.
///
/// The batch contract: 1 to 64 pairs are derived in input order; 0 pairs is `bad_batch`; more than 64 is refused
/// as a whole with `batch_too_large`, with no truncation, no partial derivation and no keys. The caller splits larger sets.
enum BeamioFragmentKeys {
	/// The most pairs one batch may hold.
	static let maxBatch = 64

	enum BatchError: String, Error, Equatable {
		case badBatch = "bad_batch"
		case batchTooLarge = "batch_too_large"
	}

	/// The info of one fragment key: `frag|<seq>|<prevCid>`. The prevCid is used as the CID string.
	static func info(seq: Int, prevCid: String) -> String {
		"frag|\(seq)|\(prevCid)"
	}

	/// The 32-byte key of one fragment (D-04, D-05).
	static func key(master: Data, seq: Int, prevCid: String) -> Data {
		BeamioConetChatHistoryStore.hkdf(master: master, info: info(seq: seq, prevCid: prevCid), length: 32)
	}

	/// The keys of a batch, in input order (D-11), or the whole-batch refusal (D-12, D-13).
	static func batch(master: Data, pairs: [(seq: Int, prevCid: String)]) -> Result<[Data], BatchError> {
		if pairs.isEmpty { return .failure(.badBatch) }
		if pairs.count > maxBatch { return .failure(.batchTooLarge) }
		return .success(pairs.map { key(master: master, seq: $0.seq, prevCid: $0.prevCid) })
	}
}
