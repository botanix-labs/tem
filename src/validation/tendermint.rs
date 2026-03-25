//! # Tendermint Validation Module
//!
//! This module provides validation capabilities for Tendermint/CometBFT
//! consensus data, including validator signature verification, chain continuity
//! validation, and validator set transitions. It implements the core consensus
//! validation logic for the Botanix network's BFT layer.
//!
//! ## Key Features
//!
//! - **Validator Signature Verification**: Validates that 2/3+ of validators
//!   have signed each block with valid cryptographic signatures
//! - **Chain Continuity**: Ensures proper block height increments and parent
//!   block references form an unbroken chain
//! - **Validator Set Transitions**: Handles changes in the validator set with
//!   proper validation of new validator announcements
//! - **Genesis Bootstrapping**: Establishes initial trust from hardcoded
//!   genesis validator set hashes
//!
//! ## Security Model
//!
//! The module implements Tendermint's BFT security assumptions, requiring:
//! - At least 2/3 of voting power must sign each block
//! - Validator signatures must be cryptographically valid
//! - Block references must form a continuous chain
//! - Validator set changes must be properly announced and validated
//!
//! ## Chain Building
//!
//! The [`CheckedTendermintChain`] type maintains a validated sequence of
//! Tendermint headers, ensuring that each new block properly extends the chain
//! and is signed by the appropriate validator set.
//!
//! ## Main Types
//!
//! - [`CheckedTendermintHeader`]: A single validated Tendermint block header
//! - [`CheckedTendermintChain`]: A validated sequence of Tendermint headers

use crate::validation::bitcoin::CheckedBitcoinHeader;
use tendermint::block::Height;
use tendermint_light_client_verifier::errors::VerificationError;
use tendermint_light_client_verifier::operations::{
    ProdCommitValidator, ProdVotingPowerCalculator,
};
use tendermint_light_client_verifier::predicates::{ProdPredicates, VerificationPredicates};
use tendermint_light_client_verifier::types::{
    Hash, Header as TendermintHeader, SignedHeader, Validator, ValidatorSet,
};

/// The hash of the genesis validator set.
/// > hex-decode("9A496A132B7A65A262A1FD59EFCC32523011B78E36FB3CBA7FFEE9259EF44751")
///
/// ```json
/// {
///     "version": {
///         "block": "11",
///         "app": "1"
///     },
///     "chain_id": "3637",
///     "height": "1",
///     "time": "2025-05-22T15:20:26.93800338Z",
///     "last_block_id": {
///         "hash": "",
///         "parts": {
///             "total": 0,
///             "hash": ""
///         }
///     },
///     "last_commit_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
///     "data_hash": "56676D8D223CBC207F8DBF86F538F4DEC3DF553CD35BA3582E1AA0009DB0120C",
///     "validators_hash": "9A496A132B7A65A262A1FD59EFCC32523011B78E36FB3CBA7FFEE9259EF44751",
///     "next_validators_hash": "9A496A132B7A65A262A1FD59EFCC32523011B78E36FB3CBA7FFEE9259EF44751",
///     "consensus_hash": "BAB5041D16246E2757DB17AF4B55FAAFBFD8660F7EB32871C99F91D0E58D5BF2",
///     "app_hash": "0210AE550E730D0E18F96896B80CAAD6F59DCC0B83B67421975716D155D027C6",
///     "last_results_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
///     "evidence_hash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
///     "proposer_address": "166CC9EC51ADDAB9DCDEAA535B091B0B91132134"
/// }
/// ```
//
// TODO: Add a hex-decode unit-test to verify this.
const GENESIS_VALIDATOR_SET_HASH: [u8; 32] = [
    154, 73, 106, 19, 43, 122, 101, 162, 98, 161, 253, 89, 239, 204, 50, 82, 48, 17, 183, 142, 54,
    251, 60, 186, 127, 254, 233, 37, 158, 244, 71, 81,
];

/// Errors that can occur during Tendermint header validation and chain
/// building.
///
/// These errors represent various validation failures that can happen when
/// verifying block headers and maintaining the integrity of a Tendermint chain.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The block references an incorrect validator set hash.
    ///
    /// This occurs when a block's `validators_hash` doesn't match the expected
    /// validator set hash for that height.
    InvalidAuthorityReference { expected: Hash, got: Hash },
    /// The block references an incorrect parent block hash.
    ///
    /// This occurs when a block's `last_block_id.hash` doesn't match the hash
    /// of the previous block in the chain.
    InvalidParentReference { expected: Hash, got: Hash },
    /// The block height is not a sequential increment from the parent. This
    /// occurs when a block's height is not exactly `parent_height + 1`.
    InvalidHeightIncrement { expected: Height, got: Height },
    /// The block header is missing the required `last_block_id` field. All
    /// non-genesis blocks must reference their parent block.
    NoLastBlockId,
    /// The provided validator set doesn't match the expected hash.
    InvalidValidatorSetMatch(VerificationError),
    /// The commit structure is invalid (wrong number of signatures, missing
    /// validators, etc.).
    InvalidCommitStructure(VerificationError),
    /// The validator signatures are invalid or insufficient voting power.
    InvalidValidatorSignatures(VerificationError),
}

/// A Tendermint header that has been validated and can be trusted.
///
/// This wrapper ensures that only headers that have passed all validation
/// checks can be used in further operations. The inner header is kept private
/// to prevent direct modification.
pub struct CheckedTendermintHeader {
    /* PRIVATE! */ _header: TendermintHeader,
}

impl AsRef<TendermintHeader> for CheckedTendermintHeader {
    fn as_ref(&self) -> &TendermintHeader {
        &self._header
    }
}

impl AsRef<[CheckedTendermintHeader]> for CheckedTendermintChain {
    fn as_ref(&self) -> &[CheckedTendermintHeader] {
        &self.chain
    }
}

/// A validated chain of Tendermint headers with cryptographic verification.
///
/// This structure maintains a sequence of validated Tendermint headers,
/// ensuring that each new header properly references its parent and is signed
/// by the correct validator set. It provides strong guarantees about the
/// integrity and validity of the chain.
///
/// # Checks
///
/// - All headers in the chain have been cryptographically validated
/// - Each header properly references its parent
/// - Each header is signed by the appropriate validator set
/// - Heights are sequential with no gaps
pub struct CheckedTendermintChain {
    v: ProdPredicates,
    // TODO: Mark this private
    chain: Vec<CheckedTendermintHeader>,
    validator_set: ValidatorSet,
    validator_set_hash: Hash,
}

impl CheckedTendermintChain {
    /// Creates a new validated Tendermint chain starting from a block signed by
    /// the genesis validators.
    ///
    /// This method validates the initial block against the hardcoded genesis
    /// validator set hash and ensures all cryptographic signatures are valid.
    ///
    /// # Arguments
    ///
    /// * `untrusted` - The initial block header with signatures to validate
    /// * `validators` - The (genesis) validator set that should match the
    ///   genesis hash
    ///
    /// # Returns
    ///
    /// A new `CheckedTendermintChain` containing the validated block, or an
    /// error if validation fails.
    ///
    /// # Errors
    ///
    /// - `InvalidValidatorSetMatch` if the provided validators don't match the
    ///   genesis hash
    /// - `InvalidAuthorityReference` if the block doesn't reference the correct
    ///   validator set
    /// - `InvalidCommitStructure` or `InvalidValidatorSignatures` for signature
    ///   validation failures
    pub fn new_via_genesis(
        untrusted: SignedHeader,
        validators: Vec<Validator>,
    ) -> Result<Self, Error> {
        // Setup production predicate verifier.
        let v = ProdPredicates::default();

        // Setup validator set without a proposer (TODO: Is that correct?)
        let proposer = None;
        let validator_set = ValidatorSet::new(validators, proposer);
        let validator_set_hash = Hash::Sha256(GENESIS_VALIDATOR_SET_HASH);

        // VALIDATE: Passed-on validator set matches the genesis validator set hash.
        v.validator_sets_match(&validator_set, validator_set_hash)
            .map_err(Error::InvalidValidatorSetMatch)?;

        // VALIDATE: Block references the genesis validator set hash.
        if untrusted.header.validators_hash != validator_set_hash {
            return Err(Error::InvalidAuthorityReference {
                expected: validator_set_hash,
                got: untrusted.header.validators_hash,
            });
        }

        // VALIDATE: Signatures and threshold requirements.
        Self::validate_commits(&v, &untrusted, &validator_set)?;

        let trusted = untrusted;

        Ok(Self {
            v,
            chain: vec![CheckedTendermintHeader {
                _header: trusted.header,
            }],
            validator_set,
            validator_set_hash,
        })
    }
    /// **WARNING**: Not implemented yet!
    ///
    /// Creates a new Tendermint chain anchored to a Bitcoin header.
    ///
    /// This method allows bootstrapping a Tendermint chain using a Bitcoin
    /// header as the root of trust, enabling cross-chain verification.
    ///
    /// # Arguments
    ///
    /// * `untrusted` - The initial Tendermint header to validate
    /// * `checked` - A validated Bitcoin header to use as the trust anchor
    ///
    /// # Returns
    ///
    /// A new `CheckedTendermintChain` or an error if validation fails.
    pub fn new_via_bitcoin(
        _untrusted: SignedHeader,
        _checked: &CheckedBitcoinHeader,
    ) -> Result<Self, ()> {
        todo!()
    }

    /// Appends a new validated header to the end of the chain.
    ///
    /// This method performs comprehensive validation to ensure the new header:
    /// - Properly references the previous block as its parent
    /// - Has a height that's exactly one more than the parent
    /// - Is signed by the correct validator set
    /// - Meets all cryptographic signature requirements
    ///
    /// # Arguments
    ///
    /// * `untrusted` - The new header to validate and append
    /// * `next_validators` - Optional new validator set if there's a validator
    ///   set change, as announced by the Tendermint block header.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the header was successfully validated and appended,
    /// or an error describing why validation failed.
    ///
    /// # Errors
    ///
    /// - `InvalidParentReference` if the block doesn't reference the correct
    ///   parent
    /// - `InvalidHeightIncrement` if the height isn't a sequential increment
    /// - `NoLastBlockId` if the block is missing parent reference
    /// - `InvalidAuthorityReference` if validator set hash doesn't match
    /// - `InvalidCommitStructure` or `InvalidValidatorSignatures` for signature
    ///   validation failures
    pub fn append_untrusted(
        &mut self,
        untrusted: SignedHeader,
        next_validators: Option<Vec<Validator>>,
    ) -> Result<(), Error> {
        // Retrieve the last CHECKED CometBFT block.
        let parent = self.chain.last().expect("chain must not be empty").as_ref();
        let expected_hash = parent.hash();

        // VALIDATE: New block references the parent block.
        let ref_parent = untrusted
            .header
            .last_block_id
            .ok_or(Error::NoLastBlockId)?
            .hash;

        if ref_parent != expected_hash {
            return Err(Error::InvalidParentReference {
                expected: expected_hash,
                got: ref_parent,
            });
        }

        // VALIDATE: New block height is a single increment of the parent.
        let expected_height = parent.height.increment();
        if untrusted.header.height != expected_height {
            return Err(Error::InvalidHeightIncrement {
                expected: expected_height,
                got: untrusted.header.height,
            });
        }

        // TODO: Should this allow cases where the new set is the same as the current set?
        if let Some(next) = next_validators {
            // Setup validator set without a proposer.
            let proposer = None;
            let next = ValidatorSet::new(next, proposer);

            // VALIDATE: Passed-on validator set matches the announced hash by the parent.
            self.v
                .validator_sets_match(&next, parent.next_validators_hash)
                .map_err(Error::InvalidValidatorSetMatch)?;

            // Update active validator set entries.
            self.validator_set = next;
            self.validator_set_hash = parent.next_validators_hash;
        }

        // VALIDATE: New block references the active validator set.
        if untrusted.header.validators_hash != self.validator_set_hash {
            return Err(Error::InvalidAuthorityReference {
                expected: self.validator_set_hash,
                got: untrusted.header.validators_hash,
            });
        }

        // VALIDATE: Signatures and threshold requirements.
        Self::validate_commits(&self.v, &untrusted, &self.validator_set)?;

        let trusted = untrusted;

        self.chain.push(CheckedTendermintHeader {
            _header: trusted.header,
        });

        Ok(())
    }
    /// Validates the cryptographic signatures and commit structure of a header.
    ///
    /// This internal method performs two levels of validation:
    /// 1. Structural validation of the commit (correct number of signatures, etc.)
    /// 2. Cryptographic validation of signatures and voting power thresholds
    ///
    /// # Arguments
    ///
    /// * `v` - The verification predicates to use for validation
    /// * `untrusted` - The signed header to validate
    /// * `validator_set` - The validator set that should have signed this header
    ///
    /// # Returns
    ///
    /// `Ok(())` if all validations pass, or an error describing the validation
    /// failure.
    fn validate_commits(
        v: &ProdPredicates,
        untrusted: &SignedHeader,
        validator_set: &ValidatorSet,
    ) -> Result<(), Error> {
        // VALIDATE: Basic properties of the commit structure:
        //
        // 1. Check the commit-sig contains at least one non-absent signature.
        // 2. Check that that the number of commit-sig's matches the number of
        //    validators.
        // 3. Check that each non-absent commit-sig address exists in the
        //    validator set.
        //
        // NOTE that this DOES NOT verify the signatures themselves.
        v.valid_commit(&untrusted, validator_set, &ProdCommitValidator)
            .map_err(Error::InvalidCommitStructure)?;

        // VALIDATE: Validator signatures of the new block:
        //
        // 1. Verify the signatures of the validators in the commit.
        // 2. Check that at least 2/3 of the voting power successfully signed in
        //    favor of the header.
        //
        // Note that this can pass even if there are invalid signatures, as long as
        // the required threshold of voting power is met.
        v.has_sufficient_signers_overlap(
            &untrusted,
            validator_set,
            &ProdVotingPowerCalculator::default(),
        )
        .map_err(Error::InvalidValidatorSignatures)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{cbft_signed_header_from_json, cbft_validator_set_from_json};

    #[test]
    fn test_validate_signed_header() {
        let validators = include_bytes!("cometbft_test_data/validators_height=672580.json");
        //
        let signed_header_parent = include_bytes!("cometbft_test_data/commit_height=672580.json");
        let signed_header_current = include_bytes!("cometbft_test_data/commit_height=672581.json");
        let signed_header_invalid = include_bytes!("cometbft_test_data/commit_height=757434.json");

        let validators = cbft_validator_set_from_json(validators).unwrap();
        //
        let signed_header_parent = cbft_signed_header_from_json(signed_header_parent).unwrap();
        let signed_header_current = cbft_signed_header_from_json(signed_header_current).unwrap();
        let signed_header_invalid = cbft_signed_header_from_json(signed_header_invalid).unwrap();

        let mut chain =
            CheckedTendermintChain::new_via_genesis(signed_header_parent, validators).unwrap();

        let err = chain
            .append_untrusted(signed_header_invalid, None)
            .unwrap_err();

        assert!(matches!(err, Error::InvalidParentReference { .. }));

        chain.append_untrusted(signed_header_current, None).unwrap();
    }
}
