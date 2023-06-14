#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod delegate_call {

    #[derive(Debug, PartialEq, Eq, Clone, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(::scale_info::TypeInfo))]
    pub enum Error {
        NotEnoughMoney,
        ErrorInvoking,
        TransferError,
        NotAnAdmin,
    }
    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct DelegateCall {
        forward_to: AccountId,
        admin: AccountId,
        addresses: [AccountId; 3],
        payouts: [Balance; 3],
        target: Hash,
    }

    impl DelegateCall {
        #[ink(constructor)]
        pub fn new(
            forward_to: AccountId,
            address1: AccountId,
            address2: AccountId,
            address3: AccountId,
            target: Hash,
        ) -> Self {
            Self {
                admin: Self::env().caller(),
                forward_to,
                addresses: [address1, address2, address3],
                payouts: [0, 0, 0],
                target: target,
            }
        }

        #[ink(message, payable, selector = _)]
        pub fn ask_payouts(&mut self, amount: Balance) -> Result<(), Error> {
            let result: (Balance, Balance, Balance) =
                ink::env::call::build_call::<ink::env::DefaultEnvironment>()
                    .delegate(self.target)
                    .exec_input(
                        ink::env::call::ExecutionInput::new(ink::env::call::Selector::new(
                            ink::selector_bytes!("payouts"),
                        ))
                        .push_arg(amount),
                    )
                    .returns::<(Balance, Balance, Balance)>()
                    .try_invoke()
                    .map_err(|_e| Error::ErrorInvoking)?;

            self.payouts[0] = result.0;
            self.payouts[1] = result.1;
            self.payouts[2] = result.2;

            Ok(())
        }

        #[ink(message)]
        pub fn set_target(&mut self, new_target: Hash) -> Result<(), Error> {
            if self.admin != self.env().caller() {
                return Err(Error::NotAnAdmin);
            }
            self.target = new_target;
            Ok(())
        }

        #[ink(message, payable)]
        pub fn pay(&mut self) -> Result<(), Error> {
            let amount = self.env().transferred_value();

            if amount <= (self.payouts[0] + self.payouts[2] + self.payouts[1]) {
                return Err(Error::NotEnoughMoney);
            }

            self.env()
                .transfer(self.addresses[0], self.payouts[0])
                .unwrap();
            self.env()
                .transfer(self.addresses[1], self.payouts[1])
                .unwrap();
            self.env()
                .transfer(self.addresses[2], self.payouts[2])
                .unwrap();

            self.payouts[0] = 0;
            self.payouts[1] = 0;
            self.payouts[2] = 0;

            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink::env::test::DefaultAccounts;

        type AccountId = <ink::env::DefaultEnvironment as ink::env::Environment>::AccountId;

        #[ink::test]
        fn constructor_works() {
            let accounts: DefaultAccounts<ink::env::DefaultEnvironment> =
                ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();
            let alice: AccountId = accounts.alice;
            let bob: AccountId = accounts.bob;
            let charlie: AccountId = accounts.charlie;
            let dave: AccountId = accounts.eve;
            let hash: Hash = [0x01; 32].into();
            let contract = DelegateCall::new(alice, bob, charlie, dave, hash);
            assert_eq!(contract.forward_to, alice);
            assert_eq!(contract.admin, alice);
            assert_eq!(contract.addresses, [bob, charlie, dave]);
            assert_eq!(contract.payouts, [0, 0, 0]);
        }

        // try to change target without being admin
        #[ink::test]
        #[should_panic(expected = "Only admin can set target")]
        fn set_target_fails() {
            let accounts: DefaultAccounts<ink::env::DefaultEnvironment> =
                ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();
            let alice: AccountId = accounts.alice;
            let bob: AccountId = accounts.bob;
            let charlie: AccountId = accounts.charlie;
            let dave: AccountId = accounts.eve;
            let hash: Hash = [0x01; 32].into();
            let mut contract = DelegateCall::new(alice, bob, charlie, dave, hash);
            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(bob); //alice is the admin
            contract.set_target([0x02; 32].into()).unwrap();
        }

        #[ink::test]
        fn set_target_doesnt_fails() {
            let accounts: DefaultAccounts<ink::env::DefaultEnvironment> =
                ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();
            let alice: AccountId = accounts.alice;
            let bob: AccountId = accounts.bob;
            let charlie: AccountId = accounts.charlie;
            let dave: AccountId = accounts.eve;
            let hash: Hash = [0x01; 32].into();
            let mut contract = DelegateCall::new(alice, bob, charlie, dave, hash);
            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(alice); //alice is the admin
            contract.set_target([0x02; 32].into()).unwrap();
        }
    }
}
