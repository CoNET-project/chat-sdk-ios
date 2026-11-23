import Foundation
import SQLite3

private let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// Bound parameter for a statement.
enum ChatLocalValue {
	case int(Int64)
	case real(Double)
	case text(String)
	case blob(Data)
	case null
}

/// Thin wrapper over the system SQLite C API. Not thread-safe by itself: the store serializes
/// every call on its own queue.
final class ChatLocalSQLite {
	private var handle: OpaquePointer?

	init(path: String) throws {
		var h: OpaquePointer?
		let rc = sqlite3_open_v2(path, &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
		guard rc == SQLITE_OK, let opened = h else {
			if let h { sqlite3_close(h) }
			throw BeamioChatLocalError.sqlite(rc)
		}
		handle = opened
		sqlite3_busy_timeout(opened, 3000)
	}

	deinit { close() }

	var isOpen: Bool { handle != nil }

	func close() {
		if let h = handle {
			sqlite3_close_v2(h)
			handle = nil
		}
	}

	func exec(_ sql: String) throws {
		guard let h = handle else { throw BeamioChatLocalError.locked }
		var err: UnsafeMutablePointer<CChar>?
		let rc = sqlite3_exec(h, sql, nil, nil, &err)
		if let err { sqlite3_free(err) }
		guard rc == SQLITE_OK else { throw BeamioChatLocalError.sqlite(rc) }
	}

	func prepare(_ sql: String) throws -> ChatLocalStatement {
		guard let h = handle else { throw BeamioChatLocalError.locked }
		var s: OpaquePointer?
		let rc = sqlite3_prepare_v2(h, sql, -1, &s, nil)
		guard rc == SQLITE_OK, let stmt = s else { throw BeamioChatLocalError.sqlite(rc) }
		return ChatLocalStatement(stmt: stmt)
	}

	/// Runs `body` inside BEGIN IMMEDIATE / COMMIT, rolling back on any error.
	func transaction<T>(_ body: () throws -> T) throws -> T {
		try exec("BEGIN IMMEDIATE")
		do {
			let result = try body()
			try exec("COMMIT")
			return result
		} catch {
			try? exec("ROLLBACK")
			throw error
		}
	}

	func run(_ sql: String, _ binds: [ChatLocalValue] = []) throws {
		let st = try prepare(sql)
		try st.bind(binds)
		try st.stepDone()
	}

	func scalarInt(_ sql: String, _ binds: [ChatLocalValue] = []) throws -> Int64 {
		let st = try prepare(sql)
		try st.bind(binds)
		guard try st.step() else { return 0 }
		return st.int(0)
	}

	func scalarText(_ sql: String, _ binds: [ChatLocalValue] = []) throws -> String? {
		let st = try prepare(sql)
		try st.bind(binds)
		guard try st.step() else { return nil }
		return st.text(0)
	}
}

final class ChatLocalStatement {
	private let stmt: OpaquePointer

	init(stmt: OpaquePointer) { self.stmt = stmt }

	deinit { sqlite3_finalize(stmt) }

	func bind(_ values: [ChatLocalValue]) throws {
		for (i, v) in values.enumerated() {
			let idx = Int32(i + 1)
			let rc: Int32
			switch v {
			case .int(let n):
				rc = sqlite3_bind_int64(stmt, idx, n)
			case .real(let d):
				rc = sqlite3_bind_double(stmt, idx, d)
			case .text(let s):
				rc = sqlite3_bind_text(stmt, idx, s, -1, sqliteTransient)
			case .blob(let d):
				rc = d.withUnsafeBytes { raw in
					sqlite3_bind_blob(stmt, idx, raw.baseAddress, Int32(d.count), sqliteTransient)
				}
			case .null:
				rc = sqlite3_bind_null(stmt, idx)
			}
			guard rc == SQLITE_OK else { throw BeamioChatLocalError.sqlite(rc) }
		}
	}

	/// Returns true for a row, false when the statement is done.
	func step() throws -> Bool {
		let rc = sqlite3_step(stmt)
		if rc == SQLITE_ROW { return true }
		if rc == SQLITE_DONE { return false }
		throw BeamioChatLocalError.sqlite(rc)
	}

	func stepDone() throws {
		_ = try step()
	}

	func int(_ i: Int32) -> Int64 { sqlite3_column_int64(stmt, i) }

	func double(_ i: Int32) -> Double { sqlite3_column_double(stmt, i) }

	func isNull(_ i: Int32) -> Bool { sqlite3_column_type(stmt, i) == SQLITE_NULL }

	func text(_ i: Int32) -> String? {
		guard !isNull(i), let c = sqlite3_column_text(stmt, i) else { return nil }
		return String(cString: c)
	}

	func blob(_ i: Int32) -> Data? {
		guard !isNull(i) else { return nil }
		let n = sqlite3_column_bytes(stmt, i)
		guard n > 0, let p = sqlite3_column_blob(stmt, i) else { return Data() }
		return Data(bytes: p, count: Int(n))
	}
}
