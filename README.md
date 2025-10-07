# 📜 ProofLayer: Immutable Document Attestation on Bitcoin

## Overview

**ProofLayer** is a Bitcoin-anchored, zero-knowledge document verification protocol deployed on the **Stacks** smart contract platform. It enables individuals and organizations to generate **permanent, tamper-proof, and privacy-preserving attestations** for digital content by storing cryptographic hashes (SHA-256) on-chain—without ever revealing the content itself.

By leveraging Bitcoin’s finality and Stacks’ smart contract capabilities, ProofLayer provides forensic-grade timestamping for legal, regulatory, and commercial use cases—eliminating the need for trusted third-party notaries or centralized timestamping authorities.

---

## ⚙️ Key Features

* 🔐 **Zero-Knowledge Privacy**: Only document hashes are stored—contents remain confidential.
* 🕒 **Immutable Timestamps**: Anchored to Bitcoin via Stacks at specific block heights.
* 🏛 **Legal & Regulatory Compliance**: Suitable for patents, contracts, IP claims, audit logs, and whistleblower protection.
* ♾ **Perpetual Validity**: No expirations, no renewals, no intermediaries.
* 🔍 **Trustless Verification**: Anyone can independently verify a document’s authenticity using its hash.
* 📈 **Audit Trail**: Track verification attempts per hash for compliance and analytics.

---

## 🚀 System Overview

ProofLayer operates as a **stateless, content-agnostic ledger of attestations**. Each attestation is a signed, timestamped claim that a document (represented by its SHA-256 hash) existed at a specific block height. The system enforces one-way trust: originators commit a hash to the blockchain; recipients and third parties can later verify authenticity **without needing to trust the originator or the platform**.

### Attestation Lifecycle

1. **Hash Creation**: Users generate a 32-byte SHA-256 hash of the document off-chain.
2. **Attestation Submission**: The hash and recipient address are submitted via `create-attestation`.
3. **On-chain Recording**: An immutable entry is stored with originator, recipient, timestamp, and block height.
4. **Verification**: Any party can call `verify-attestation` by submitting the attestation ID and hash. The protocol validates without revealing document content.

---

## 🧱 Contract Architecture

| Component                    | Description                                             |
| ---------------------------- | ------------------------------------------------------- |
| `attestations`               | Core ledger: maps attestation IDs to proof metadata     |
| `hash-verification-registry` | Index for reverse lookup and verification analytics     |
| `user-attestation-count`     | Tracks how many attestations each principal has created |
| `total-attestations` (var)   | Global attestation counter                              |
| `protocol-version` (var)     | Current semantic version of the protocol                |
| `CONTRACT_OWNER` (constant)  | The deployer with access to protocol version upgrades   |

### Key Methods

#### ✅ Public Functions

* `create-attestation(recipient, content-hash)`

  * Submits an attestation binding sender, recipient, and hash at a given block.
* `verify-attestation(attestation-id, provided-hash)`

  * Validates hash authenticity, updates verification status, and tracks usage.
* `update-protocol-version(new-version)`

  * Owner-only method to upgrade protocol version (non-downgrade enforced).

#### 📖 Read-Only Queries

* `get-attestation-info(attestation-id)`
* `get-user-attestation-count(user)`
* `get-total-attestations`
* `get-protocol-version`
* `hash-exists(hash)`
* `get-verification-attempts(hash)`

---

## 🔄 Data Flow

```
            +-------------------------+
            |   Off-chain Document    |
            |      (user input)       |
            +-----------+-------------+
                        |
                        | SHA-256 Hash
                        v
         +--------------+-------------------+
         | ProofLayer Smart Contract (Clarity) |
         | - Stores hash, timestamp, actors   |
         | - Immutable & permanent             |
         +----------------+------------------+
                          |
             +------------+------------+
             |                         |
      Attestation ID          Reverse Lookup (hash index)
             |                         |
     Retrieve & verify        Query attempts / existence
```

---

## ✅ Security & Validation Rules

* **Self-Attestation Blocked**: Originators cannot attest to themselves.
* **Valid Hash Format Required**: Only 32-byte SHA-256 digests accepted.
* **Address Integrity**: Null addresses rejected.
* **Attestation ID Validity**: All lookups enforce positive ID range.
* **Upgrade Access Control**: Only contract owner can update protocol version.

---

## 🔐 Example Use Cases

| Use Case                   | How ProofLayer Helps                                     |
| -------------------------- | -------------------------------------------------------- |
| **Patent Priority Claims** | Prove prior invention without exposing technical details |
| **Legal Contracts**        | Timestamp signed agreements with immutable custody chain |
| **Regulatory Logs**        | Record audit trails and data disclosures                 |
| **IP/Creative Works**      | Timestamp original versions for dispute protection       |
| **Whistleblower Proofs**   | Submit verifiable hashes without revealing identity      |

---

## 🧪 Testing and Deployment

To test locally or deploy on Stacks testnet:

```bash
clarinet test       # Run unit tests
clarinet check      # Typecheck & analyze
clarinet deploy     # Deploy to testnet
```

### Deployment Notes

* Ensure the deploying principal becomes the protocol owner (`CONTRACT_OWNER`).
* Only the owner can update `protocol-version`.
* Once deployed, attestations are immutable and cannot be deleted.

---

## 🧩 Future Enhancements

* Merkle tree support for batch attestations
* zk-SNARK integration for additional privacy layers
* Support for multi-signature attestations
* UI dashboard for verification and analytics
* API gateway for enterprise integrations

---

## 📄 License

This project is released under the **MIT License**.
