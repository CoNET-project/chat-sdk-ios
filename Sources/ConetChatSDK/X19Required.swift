// X-19 (native OpenPGP) is linked into every iOS build of this SDK. A build without the artifact fails here, with the way to get it.
// On macOS the SDK does not depend on X-19, so this check does not apply there.
#if os(iOS) && !canImport(X19)
#error("X-19 is missing from this iOS build: run scripts/x19/install-x19.sh (development) or fetch the locked artifact (scripts/x19/X19.artifact.lock).")
#endif
