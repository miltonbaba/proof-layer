;; Title: ProofLayer
;;
;; Summary:
;; ProofLayer creates an immutable timestamping infrastructure on Bitcoin through
;; Stacks, enabling permanent cryptographic verification of digital documents.
;; Store SHA-256 hashes on-chain while keeping content private-establishing
;; provable authenticity for intellectual property, legal agreements, and
;; regulatory compliance without intermediaries or expiration dates.
;;
;; Description:
;; ProofLayer transforms Bitcoin into a global notary service by anchoring
;; cryptographic fingerprints directly to its immutable ledger. The protocol
;; employs zero-knowledge architecture: only document hashes reach the blockchain,
;; ensuring absolute confidentiality while maintaining mathematical proof of
;; existence. Each attestation binds originators to recipients at precise block
;; heights, creating forensic-grade evidence chains that satisfy legal discovery
;; requirements. Unlike traditional notarization requiring trusted third parties
;; and renewal fees, ProofLayer offers permanent verification backed by Bitcoin's
;; hash power-attestations remain accessible indefinitely with no maintenance
;; costs. The system addresses critical use cases: establishing patent priority
;; dates, protecting whistleblower submissions, generating regulatory audit logs,
;; and timestamping commercial contracts. Verification occurs trustlessly-anyone
;; can validate document authenticity using only the hash, never exposing
;; underlying content. By harnessing Stacks' Bitcoin settlement finality,
;; ProofLayer delivers enterprise-grade security with decentralized transparency,
;; redefining standards for digital evidence and intellectual property protection
;; in an era where data integrity determines value and trust.
;;
;; TL;DR:
;; Bitcoin-anchored document verification protocol. Hash documents, store them
;; permanently on Bitcoin via Stacks, verify authenticity anytime without
;; revealing content. Ideal for patents, legal records, compliance-zero
;; intermediaries, infinite lifespan, cryptographic certainty.
;;

;; CONSTANTS & ERROR CODES

;; Error codes for contract operations
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INVALID_MESSAGE (err u101))
(define-constant ERR_MESSAGE_NOT_FOUND (err u102))
(define-constant ERR_INVALID_HASH (err u103))
(define-constant ERR_INVALID_RECIPIENT (err u104))
(define-constant ERR_INVALID_VERSION (err u105))
(define-constant ERR_SELF_ATTESTATION (err u106))

;; Protocol constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant NULL_ADDRESS 'SP000000000000000000002Q6VF78)

;; STATE VARIABLES

(define-data-var total-attestations uint u0)
(define-data-var protocol-version uint u1)

;; DATA STRUCTURES

;; Primary attestation ledger - immutable proof records
(define-map attestations
  { attestation-id: uint }
  {
    originator: principal,
    recipient: principal,
    content-hash: (buff 32),
    timestamp: uint,
    block-height: uint,
    verification-status: bool
  }
)

;; User activity tracking
(define-map user-attestation-count
  { user: principal }
  { count: uint }
)

;; Hash registry for reverse lookups and audit trails
(define-map hash-verification-registry
  { content-hash: (buff 32) }
  { 
    attestation-id: uint,
    verification-attempts: uint
  }
)

;; PRIVATE HELPER FUNCTIONS

(define-private (is-valid-hash (hash (buff 32)))
  (> (len hash) u0)
)

(define-private (is-valid-principal (user principal))
  (not (is-eq user NULL_ADDRESS))
)

(define-private (increment-attestation-count (user principal))
  (let 
    (
      (current-count (default-to u0 
        (get count (map-get? user-attestation-count { user: user }))
      ))
    )
    (map-set user-attestation-count 
      { user: user }
      { count: (+ current-count u1) }
    )
  )
)

;; PUBLIC CORE FUNCTIONS

;; Creates an immutable attestation record anchored to Bitcoin through Stacks.
;; Establishes cryptographic proof of document existence at a specific block
;; height by storing its SHA-256 hash on-chain, creating a verifiable chain
;; of custody between originator and recipient without exposing content.
;;
;; @param recipient: Principal receiving the attestation (must differ from sender)
;; @param content-hash: 32-byte SHA-256 hash of the content being notarized
;;
;; @returns: (response uint uint) - Unique attestation ID on success
;;
;; Security: Prevents self-attestation, validates hash format and principal integrity
(define-public (create-attestation 
  (recipient principal) 
  (content-hash (buff 32))
)
  (let 
    (
      (attestation-id (+ (var-get total-attestations) u1))
      (current-block stacks-block-height)
    )
    ;; Validation checks
    (asserts! (is-valid-principal recipient) ERR_INVALID_RECIPIENT)
    (asserts! (is-valid-hash content-hash) ERR_INVALID_HASH)
    (asserts! (not (is-eq tx-sender recipient)) ERR_SELF_ATTESTATION)
    
    ;; Store attestation with metadata
    (map-set attestations
      { attestation-id: attestation-id }
      {
        originator: tx-sender,
        recipient: recipient,
        content-hash: content-hash,
        timestamp: current-block,
        block-height: current-block,
        verification-status: false
      }
    )
    
    ;; Create hash index for reverse lookups
    (map-set hash-verification-registry
      { content-hash: content-hash }
      {
        attestation-id: attestation-id,
        verification-attempts: u1
      }
    )
    
    ;; Update state
    (var-set total-attestations attestation-id)
    (increment-attestation-count tx-sender)
    
    (ok attestation-id)
  )
)

;; Performs zero-knowledge verification by comparing a provided hash against
;; the stored attestation record. Confirms document authenticity without
;; accessing original content, preserving privacy while proving integrity.
;; Updates verification status and increments audit counter on success.
;;
;; @param attestation-id: Unique identifier of the attestation to verify
;; @param provided-hash: Hash to validate against the on-chain record
;;
;; @returns: (response bool uint) - true if hashes match, false otherwise
;;
;; Security: Validates attestation existence and hash format before comparison
(define-public (verify-attestation 
  (attestation-id uint) 
  (provided-hash (buff 32))
)
  (let 
    (
      (attestation-record (unwrap! 
        (map-get? attestations { attestation-id: attestation-id }) 
        ERR_MESSAGE_NOT_FOUND
      ))
      (stored-hash (get content-hash attestation-record))
    )
    ;; Input validation
    (asserts! (is-valid-hash provided-hash) ERR_INVALID_HASH)
    (asserts! (> attestation-id u0) ERR_INVALID_MESSAGE)
    
    (if (is-eq stored-hash provided-hash)
      (begin
        ;; Mark as verified
        (map-set attestations
          { attestation-id: attestation-id }
          (merge attestation-record { verification-status: true })
        )
        
        ;; Update verification counter
        (let 
          (
            (registry-entry (default-to 
              { attestation-id: u0, verification-attempts: u0 } 
              (map-get? hash-verification-registry { content-hash: provided-hash })
            ))
          )
          (map-set hash-verification-registry
            { content-hash: provided-hash }
            {
              attestation-id: attestation-id,
              verification-attempts: (+ (get verification-attempts registry-entry) u1)
            }
          )
        )
        (ok true)
      )
      (ok false)
    )
  )
)

;; Updates protocol version number (owner-only).
;; Enforces version increment to prevent downgrades.
;;
;; @param new-version: New semantic version number (must be greater than current)
;;
;; @returns: (response bool uint) - Success status
;;
;; Security: Restricted to contract owner, validates version progression
(define-public (update-protocol-version (new-version uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (> new-version (var-get protocol-version)) ERR_INVALID_VERSION)
    (var-set protocol-version new-version)
    (ok true)
  )
)

;; READ-ONLY QUERY FUNCTIONS

;; Retrieves complete attestation record including originator, recipient,
;; hash, timestamp, block height, and verification status.
;;
;; @param attestation-id: Target attestation identifier
;;
;; @returns: (response (optional {...}) uint) - Full attestation data or none
(define-read-only (get-attestation-info (attestation-id uint))
  (begin
    (asserts! (> attestation-id u0) ERR_INVALID_MESSAGE)
    (ok (map-get? attestations { attestation-id: attestation-id }))
  )
)

;; Returns total number of attestations created by a specific user.
;;
;; @param user: Principal to query
;;
;; @returns: (response uint uint) - Count of user's attestations
(define-read-only (get-user-attestation-count (user principal))
  (begin
    (asserts! (is-valid-principal user) ERR_INVALID_RECIPIENT)
    (ok (default-to u0 
      (get count (map-get? user-attestation-count { user: user }))
    ))
  )
)

;; Returns protocol-wide attestation counter.
;;
;; @returns: (response uint uint) - Total attestations since deployment
(define-read-only (get-total-attestations)
  (ok (var-get total-attestations))
)

;; Returns current protocol version for compatibility checking.
;;
;; @returns: (response uint uint) - Semantic version number
(define-read-only (get-protocol-version)
  (ok (var-get protocol-version))
)

;; Checks if a hash exists in the attestation registry.
;;
;; @param hash: 32-byte SHA-256 digest to check
;;
;; @returns: (response bool uint) - true if hash is registered, false otherwise
(define-read-only (hash-exists (hash (buff 32)))
  (begin
    (asserts! (is-valid-hash hash) ERR_INVALID_HASH)
    (ok (is-some (map-get? hash-verification-registry { content-hash: hash })))
  )
)

;; Retrieves total verification attempts for a specific hash.
;; Useful for audit trails and attestation usage analytics.
;;
;; @param hash: Content hash to query
;;
;; @returns: (response uint uint) - Number of verification attempts
(define-read-only (get-verification-attempts (hash (buff 32)))
  (begin
    (asserts! (is-valid-hash hash) ERR_INVALID_HASH)
    (ok (default-to u0 
      (get verification-attempts 
        (map-get? hash-verification-registry { content-hash: hash })
      )
    ))
  )
)