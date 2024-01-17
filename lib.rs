#![cfg_attr(not(feature = "std"), no_std, no_main)]

pub use reclaim::ReclaimRef;

#[ink::contract]
mod reclaim {
    use ecdsa::RecoveryId;
    use ink::prelude::string::String;
    use ink::prelude::string::ToString;
    use ink::prelude::vec::Vec;
    use ink::prelude::{format, vec};
    use ink::storage::Mapping;
    use k256::ecdsa::{Signature, VerifyingKey};
    use keccak_hash::keccak256;
    use sha2::{Digest, Sha256};

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct Witness {
        pub address: String,
        pub host: [u8; 32],
    }

    impl Witness {
        pub fn get_addresses(witness: Vec<Witness>) -> Vec<String> {
            let mut vec_addresses = vec![];
            for wit in witness {
                vec_addresses.push(wit.address);
            }
            vec_addresses
        }
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct Epoch {
        pub id: u128,
        pub timestamp_start: u64,
        pub timestamp_end: u64,
        pub minimum_witness_for_claim_creation: u128,
        pub witness: Vec<Witness>,
    }

    fn generate_random_seed(bytes: Vec<u8>, offset: usize) -> u32 {
        let hash_slice = &bytes[offset..offset + 4];
        let mut seed = 0u32;
        for (i, &byte) in hash_slice.iter().enumerate() {
            seed |= u32::from(byte) << (i * 8);
        }

        seed
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct ClaimInfo {
        pub provider: String,
        pub parameters: String,
        pub context: String,
    }

    impl ClaimInfo {
        pub fn hash(&self) -> Vec<u8> {
            let mut hasher = Sha256::new();
            let hash_str = format!(
                "{}\n{}\n{}",
                &self.provider, &self.parameters, &self.context
            );
            hasher.update(hash_str.as_bytes());
            hasher.finalize().to_vec()
        }
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct CompleteClaimData {
        pub identifier: Vec<u8>,
        pub owner: String,
        pub epoch: u128,
        pub timestamp_s: u64,
    }

    impl CompleteClaimData {
        pub fn serialise(&self) -> Vec<u8> {
            let hash_str = format!(
                "{}\n{}\n{}\n{}",
                hex::encode(&self.identifier),
                self.owner,
                &self.timestamp_s.to_string(),
                &self.epoch.to_string()
            );
            hash_str.as_bytes().to_vec()
        }
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    pub struct SignedClaim {
        pub claim: CompleteClaimData,
        pub bytes: Vec<(String, u8)>,
    }

    impl SignedClaim {
        pub fn recover_signers_of_signed_claim(self) -> Vec<String> {
            let mut expected = vec![];
            let mut hasher = Sha256::new();
            let serialised_claim = self.claim.serialise();
            hasher.update(serialised_claim);
            let mut result = hasher.finalize().to_vec();
            keccak256(&mut result);
            for (signature, recid_8) in self.bytes {
                let arr = Self::recover_raw_signature(signature);
                let slice_arr = arr.as_slice();
                let sig = Signature::try_from(slice_arr).unwrap();
                let recid = RecoveryId::try_from(recid_8).unwrap();
                let recovered_key =
                    VerifyingKey::recover_from_prehash(&result, &sig, recid).unwrap();

                let str_recovered_key = format!("{:?}", recovered_key);
                expected.push(str_recovered_key);
            }

            expected
        }

        pub fn fetch_witness_for_claim(
            epoch: Epoch,
            identifier: Vec<u8>,
            claim_timestamp: u128,
        ) -> Vec<Witness> {
            let mut selected_witness = vec![];
            let hash_str = format!(
                "{}\n{}\n{}\n{}",
                hex::encode(identifier),
                epoch.minimum_witness_for_claim_creation,
                claim_timestamp,
                epoch.id
            );
            let result = hash_str.as_bytes().to_vec();
            let mut hasher = Sha256::new();
            hasher.update(result);
            let hash_result = hasher.finalize().to_vec();
            let witenesses_left_list = epoch.witness;
            let mut byte_offset = 0;
            let witness_left = witenesses_left_list.len();
            for _i in 0..epoch.minimum_witness_for_claim_creation {
                let random_seed = generate_random_seed(hash_result.clone(), byte_offset) as usize;
                let witness_index = random_seed % witness_left;
                let witness = witenesses_left_list.get(witness_index);
                if let Some(data) = witness {
                    selected_witness.push(data.clone())
                };
                byte_offset = (byte_offset + 4) % hash_result.len();
            }

            selected_witness
        }

        pub fn recover_raw_signature(signature: String) -> [u8; 64]{
            let ss = signature.as_str();
                let sss = &ss[28..156].to_lowercase();
                let sss_str = sss.as_str();
                let mut arr = [0_u8; 64];
                for i in 0..64 {
                    let ss = &sss_str[(2 * i)..(2 * i + 2)];
                    let z = u8::from_str_radix(ss, 16).unwrap();
                    arr[i] = z;
                }
                arr
        }
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ReclaimError {
        OnlyOwner,
        AlreadyInitialized,
        HashMismatch,
        LengthMismatch,
        SignatureMismatch,
    }

    #[ink(event)]
    pub struct EpochAdded {
        epoch_id: u128,
    }

    #[ink(event)]
    pub struct ProofVerified {
        epoch_id: u128,
    }

    #[ink(storage)]
    pub struct Reclaim {
        pub owner: AccountId,
        pub current_epoch: u128,
        pub epochs: Mapping<u128, Epoch>,
    }

    impl Default for Reclaim {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Reclaim {
        #[ink(constructor)]
        pub fn new() -> Self {
            let owner = Self::env().caller();
            let current_epoch = 0_u128;
            let epochs = Mapping::new();
            Self {
                owner,
                current_epoch,
                epochs,
            }
        }

        #[ink(message)]
        pub fn add_epoch(
            &mut self,
            witness: Vec<Witness>,
            minimum_witness: u128,
        ) -> Result<(), ReclaimError> {
            let caller = Self::env().caller();
            if self.owner != caller {
                return Err(ReclaimError::OnlyOwner);
            }
            let new_epoch_id = self.current_epoch + 1_u128;
            let now = ink::env::block_timestamp::<ink::env::DefaultEnvironment>();
            let epoch = Epoch {
                id: new_epoch_id,
                witness,
                timestamp_start: now,
                timestamp_end: now + 10000_u64,
                minimum_witness_for_claim_creation: minimum_witness,
            };
            self.epochs.insert(new_epoch_id, &epoch);
            self.current_epoch = new_epoch_id;
            Self::env().emit_event(EpochAdded {
                epoch_id: new_epoch_id,
            });
            Ok(())
        }

        #[ink(message)]
        pub fn verify_proof(
            &mut self,
            claim_info: ClaimInfo,
            signed_claim: SignedClaim,
        ) -> Result<(), ReclaimError> {
            let epoch_count = self.current_epoch;
            let current_epoch = self.epochs.get(epoch_count).unwrap();
            let hashed = claim_info.hash();
            if signed_claim.claim.identifier != hashed {
                return Err(ReclaimError::HashMismatch);
            }
            let expected_witness = crate::reclaim::SignedClaim::fetch_witness_for_claim(
                current_epoch.clone(),
                signed_claim.claim.identifier.clone(),
                signed_claim.claim.timestamp_s.into(),
            );
            let expected_witness_addresses = Witness::get_addresses(expected_witness);

            let signed_witness = signed_claim.recover_signers_of_signed_claim();

            if expected_witness_addresses.len() != signed_witness.len() {
                return Err(ReclaimError::LengthMismatch);
            }
            for signed in signed_witness {
                if !expected_witness_addresses.contains(&signed) {
                    return Err(ReclaimError::SignatureMismatch);
                }
            }
            Self::env().emit_event(ProofVerified {
                epoch_id: current_epoch.id,
            });
            Ok(())
        }

        #[ink(message)]
        pub fn get_owner(&self) -> AccountId {
            self.owner
        }

        #[ink(message)]
        pub fn get_current_epoch(&self) -> u128 {
            self.current_epoch
        }
    }

    #[cfg(test)]
    mod tests {
        use ink::env::test::{default_accounts, DefaultAccounts};
        use k256::ecdsa::SigningKey;
        use rand_core::OsRng;

        use super::*;

        fn get_default_test_accounts() -> DefaultAccounts<ink::env::DefaultEnvironment> {
            default_accounts::<ink::env::DefaultEnvironment>()
        }

        fn set_caller(caller: AccountId) {
            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(caller);
        }

        #[ink::test]
        fn init() {
            let accounts = get_default_test_accounts();
            let alice = accounts.alice;
            set_caller(alice);
            let reclaim = Reclaim::new();
            assert_eq!(reclaim.get_owner(), alice);
            assert_eq!(reclaim.get_current_epoch(), 0_u128);
        }

        #[ink::test]
        fn should_add_epochs() {
            let mut reclaim = Reclaim::new();
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = VerifyingKey::from(&signing_key);
            let str_verifying_key = format!("{:?}", verifying_key);
            let w1 = Witness {
                address: str_verifying_key,
                host: [1_u8; 32],
            };
            let mut witnesses_vec = Vec::<Witness>::new();
            witnesses_vec.push(w1);
            let minimum_witness = 1;
            assert_eq!(reclaim.add_epoch(witnesses_vec, minimum_witness), Ok(()));
        }

        #[ink::test]
        fn should_approve_valid_proofs() {
            let mut reclaim = Reclaim::new();
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = VerifyingKey::from(&signing_key);
            let str_verifying_key = format!("{:?}", verifying_key);
            let w1 = Witness {
                address: str_verifying_key.clone(),
                host: [1_u8; 32],
            };
            let mut witnesses_vec = Vec::<Witness>::new();
            witnesses_vec.push(w1);
            let minimum_witness = 1;
            assert_eq!(reclaim.add_epoch(witnesses_vec, minimum_witness), Ok(()));
            let claim_info = ClaimInfo {
                provider: "provider".to_string(),
                parameters: "{}".to_string(),
                context: "context".to_string(),
            };
            let hashed = claim_info.hash();
            let now = ink::env::block_timestamp::<ink::env::DefaultEnvironment>();
            let complete_claim_data = CompleteClaimData {
                identifier: hashed,
                owner: str_verifying_key,
                epoch: 1_u128,
                timestamp_s: now,
            };
            let mut hasher = Sha256::new();
            let serialised_claim = complete_claim_data.serialise();
            hasher.update(serialised_claim);
            let mut result = hasher.finalize().to_vec();
            keccak256(&mut result);
            let mut sigs = Vec::new();
            let (signature, recid) = signing_key.sign_prehash_recoverable(&result).unwrap();
            let str_signature = format!("{:?}", signature);

            let recid_8: u8 = recid.try_into().unwrap();
            sigs.push((str_signature, recid_8));

            let signed_claim = SignedClaim {
                claim: complete_claim_data,
                bytes: sigs,
            };
            assert_eq!(reclaim.verify_proof(claim_info, signed_claim), Ok(()));
        }

        #[ink::test]
        fn should_not_approve_invalid_proofs() {
            let mut reclaim = Reclaim::new();
            let signing_key = SigningKey::random(&mut OsRng);
            let faulty_signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = VerifyingKey::from(&signing_key);
            let str_verifying_key = format!("{:?}", verifying_key);
            let w1 = Witness {
                address: str_verifying_key.clone(),
                host: [1_u8; 32],
            };
            let mut witnesses_vec = Vec::<Witness>::new();
            witnesses_vec.push(w1);
            let minimum_witness = 1;
            assert_eq!(reclaim.add_epoch(witnesses_vec, minimum_witness), Ok(()));
            let claim_info = ClaimInfo {
                provider: "provider".to_string(),
                parameters: "{}".to_string(),
                context: "context".to_string(),
            };
            let hashed = claim_info.hash();
            let now = ink::env::block_timestamp::<ink::env::DefaultEnvironment>();
            let complete_claim_data = CompleteClaimData {
                identifier: hashed,
                owner: str_verifying_key,
                epoch: 1_u128,
                timestamp_s: now,
            };
            let mut hasher = Sha256::new();
            let serialised_claim = complete_claim_data.serialise();
            hasher.update(serialised_claim);
            let mut result = hasher.finalize().to_vec();
            keccak256(&mut result);
            let mut sigs = Vec::new();
            let (signature, recid) = faulty_signing_key
                .sign_prehash_recoverable(&result)
                .unwrap();
            let str_signature = format!("{:?}", signature);

            let recid_8: u8 = recid.try_into().unwrap();
            sigs.push((str_signature, recid_8));

            let signed_claim = SignedClaim {
                claim: complete_claim_data,
                bytes: sigs,
            };
            assert_eq!(
                reclaim.verify_proof(claim_info, signed_claim),
                Err(ReclaimError::SignatureMismatch)
            );
        }
    }
}
