// This module implements a CONIKS key directory that a CONIKS key server
// maintains.
// A directory is a publicly auditable, tamper-evident, privacy-preserving
// data structure that contains mappings from usernames to public keys.
// It currently supports registration, latest-version key lookups, past key
// lookups, and monitoring.
// It does not yet support key changes.

package directory

