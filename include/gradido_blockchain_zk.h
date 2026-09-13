#ifndef GRADIDO_BLOCKCHAIN_ZK_H
#define GRADIDO_BLOCKCHAIN_ZK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! Field elements cross the boundary as 32-byte little-endian (Pallas base field). */
#define GRDZK_VALUE_BYTES 32

/*! Shielded inputs / outputs per bundle. Fixed for now; padding is a privacy requirement,
 *  see privacy_todo.md §5. */
#define GRDZK_N_IN  2
#define GRDZK_N_OUT 2

#define GRDZK_OK                 0
#define GRDZK_ERR_NULL_POINTER  -1
#define GRDZK_ERR_BAD_ARITY     -2
#define GRDZK_ERR_BAD_VALUE     -3   /*!< not a canonical field element */
#define GRDZK_ERR_PROVE_FAILED  -4   /*!< witness does not satisfy the constraints */
#define GRDZK_ERR_VERIFY_FAILED -5   /*!< proof invalid for this sighash */
#define GRDZK_ERR_UNBALANCED    -6   /*!< sum(inputs) != sum(outputs) */
#define GRDZK_ERR_VALUE_RANGE   -7   /*!< a value is >= 2^160 */
#define GRDZK_ERR_PANIC        -99

/*! Owned byte buffer handed over from Rust. Release with grdzk_buffer_free. */
typedef struct grdzk_buffer {
    uint8_t* data;
    size_t   len;
} grdzk_buffer;

/*! Library version string, valid for the lifetime of the process. */
const char* grdzk_version(void);

/* ------------------------------------------------------------------ legacy skeleton
 *
 * grdzk_init, grdzk_prove and grdzk_verify belong to the first skeleton circuit (value
 * conservation over anchored values, the dropped decision E2). They prove nothing about notes,
 * keys or decay and must not be used to validate transfers; use grdzk_bundle_verify. Kept only
 * for the measurements in the README.
 */

/*! Build the keys of the skeleton circuit eagerly.
 *  \return GRDZK_OK or GRDZK_ERR_PANIC */
int32_t grdzk_init(void);

/*! Skeleton: prove that sum(inputs) == sum(outputs), bound to sighash.
 *  Each value must be in [0, 2^160).
 *
 *  \param inputs   n_in consecutive 32-byte little-endian values
 *  \param n_in     must equal GRDZK_N_IN
 *  \param outputs  n_out consecutive 32-byte little-endian values
 *  \param n_out    must equal GRDZK_N_OUT
 *  \param sighash  32 bytes little-endian, binds the proof to the transaction body
 *  \param out      receives the proof on success; caller must grdzk_buffer_free it
 *  \return GRDZK_OK or one of the GRDZK_ERR_* codes */
int32_t grdzk_prove(
    const uint8_t* inputs,
    size_t         n_in,
    const uint8_t* outputs,
    size_t         n_out,
    const uint8_t* sighash,
    grdzk_buffer*  out
);

/*! Verify a proof produced by grdzk_prove.
 *  \return GRDZK_OK, GRDZK_ERR_VERIFY_FAILED or another GRDZK_ERR_* code */
int32_t grdzk_verify(const uint8_t* proof, size_t proof_len, const uint8_t* sighash);

/*! Release a buffer returned by grdzk_prove. Safe on an already-empty buffer. */
void grdzk_buffer_free(grdzk_buffer* buf);

/* ====================================================================== shielded transfers
 *
 * What a node needs:
 *   grdzk_bundle_verify        proof and signatures of a shielded transfer
 *   grdzk_tree_*               note commitment tree; its roots are the valid anchors
 *   grdzk_creation_commitment  note commitment of a public creation (E7)
 *
 * Anchor history and nullifier set stay in the node, in LMDB. It takes anchor, nullifiers and
 * note commitments from the effects grdzk_bundle_verify returns, never from its own protobuf
 * parser, so what it checks and appends is exactly what the proof covered. Field elements are
 * 32 bytes little-endian and must be canonical.
 *
 * Pointers must not be NULL, even with a length of 0.
 */

#define GRDZK_ERR_WIRE          -10  /*!< ShieldedBundle/ShieldedAuthorization malformed */
#define GRDZK_ERR_PROOF         -11  /*!< proof does not verify */
#define GRDZK_ERR_SPEND_AUTH    -12  /*!< a spend authorisation signature is invalid */
#define GRDZK_ERR_BINDING       -13  /*!< binding signature invalid: values do not balance */
#define GRDZK_ERR_BAD_ADDRESS   -14  /*!< not a valid 43-byte raw address */
#define GRDZK_ERR_TREE_FULL     -15

/*! Actions per bundle, and the size of the effects grdzk_bundle_verify returns. */
#define GRDZK_BUNDLE_ACTIONS      2
#define GRDZK_BUNDLE_EFFECTS_SIZE (32 + 64 * GRDZK_BUNDLE_ACTIONS)

/*! Build the keys of the shielded transfer circuit up front (about a second). */
int32_t grdzk_bundle_init(void);

/*! Verify proof and signatures of a shielded transfer. Thread-safe.
 *
 *  The encodings must be canonical (as the Rust encoder writes them); pass the bytes exactly as
 *  they appear in the transaction, do not re-encode them.
 *
 *  \param shielded       serialised ShieldedBundle (inside the transaction body)
 *  \param authorization  serialised ShieldedAuthorization (next to the body)
 *  \param community      32 bytes, field element of the transaction's community
 *  \param now            TransactionBody.created_at in seconds
 *  \param sighash        32 bytes the signatures cover, grdzk_body_sighash(body_bytes)
 *  \param out_effects    GRDZK_BUNDLE_EFFECTS_SIZE bytes, written on success:
 *                        anchor root | nullifier 0 | cm 0 | nullifier 1 | cm 1
 *  \return GRDZK_OK or GRDZK_ERR_WIRE / _PROOF / _SPEND_AUTH / _BINDING / another code */
int32_t grdzk_bundle_verify(
    const uint8_t* shielded,
    size_t         shielded_len,
    const uint8_t* authorization,
    size_t         authorization_len,
    const uint8_t* community,
    uint64_t       now,
    const uint8_t* sighash,
    uint8_t*       out_effects
);

/*! The sighash of a transaction: BLAKE2b-256 (personalisation "Gradido_BodySigh") over
 *  GradidoTransaction.body_bytes, 32 bytes into out. This is the sighash for
 *  grdzk_bundle_verify, and what the owner's device signed after checking the body. */
int32_t grdzk_body_sighash(const uint8_t* body, size_t body_len, uint8_t* out);

/*! Opaque note commitment tree. Not thread-safe: one owner, or a lock around every call
 *  (grdzk_tree_root included). */
typedef struct GrdzkTree GrdzkTree;

/*! A new, empty tree; release with grdzk_tree_free. It lives in memory: rebuild it at startup
 *  by appending the stored commitments in their order. NULL on failure. */
GrdzkTree* grdzk_tree_new(void);
void grdzk_tree_free(GrdzkTree* tree);

/*! Append one 32-byte note commitment.
 *  \return GRDZK_OK, GRDZK_ERR_BAD_VALUE (not canonical) or GRDZK_ERR_TREE_FULL (2^32 notes) */
int32_t grdzk_tree_append(GrdzkTree* tree, const uint8_t* cm);

/*! Seal the tree after a confirmed transaction. */
int32_t grdzk_tree_checkpoint(GrdzkTree* tree);

/*! Current root, 32 bytes into out. */
int32_t grdzk_tree_root(const GrdzkTree* tree, uint8_t* out);

/*! Number of notes in the tree = position of the next note. */
int32_t grdzk_tree_size(const GrdzkTree* tree, uint64_t* out);

/*! Note commitment of a public creation.
 *  \param value         GradidoUnit, below 2^63
 *  \param created_at    seconds, below 2^40
 *  \param expiry_epoch  below 2^16
 *  \param address       raw address, 43 bytes: diversifier (11) and compressed pk_d (32)
 *  \param position      leaf position the note gets (grdzk_tree_size before appending it);
 *                       the note's rho is derived from it, so identical creations stay distinct
 *  \param rseed         32 bytes, published with the creation
 *  \param memo_cm       32 bytes, commitment to the encrypted memo
 *  \param out_cm        receives the 32-byte note commitment
 *  \return GRDZK_OK, GRDZK_ERR_BAD_ADDRESS, or GRDZK_ERR_BAD_VALUE for a field out of range */
int32_t grdzk_creation_commitment(
    const uint8_t* community,
    uint64_t       value,
    uint64_t       created_at,
    uint64_t       expiry_epoch,
    const uint8_t* address,
    uint64_t       position,
    const uint8_t* rseed,
    const uint8_t* memo_cm,
    uint8_t*       out_cm
);

#ifdef __cplusplus
}
#endif

#endif /* GRADIDO_BLOCKCHAIN_ZK_H */
