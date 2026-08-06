/**
 * VectorLedger TypeScript client — public API surface.
 *
 * @packageDocumentation
 */

export { VledgerClient }                                    from "./client";
export type { VledgerClientOptions }                        from "./client";
export { VledgerError, VledgerConnectionError, Row }        from "./types";
export type { QueryResult, MerkleProof }                    from "./types";
