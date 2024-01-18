use std::time::{Duration, SystemTime};

use candid::Encode;
use ic_agent::{
    agent::EnvelopeContent,
    export::Principal,
    identity::{DelegatedIdentity, Delegation, Secp256k1Identity, SignedDelegation},
    Identity,
};
use ic_types::messages::{
    HttpCallContent, HttpCanisterUpdate, HttpRequest, HttpRequestEnvelope, SignedIngressContent,
};
use ic_validator_ingress_message::{HttpRequestVerifier, IngressMessageVerifier};

// Identity Generation
fn generate_delegated_identity() -> (Secp256k1Identity, DelegatedIdentity) {
    let priv_key = k256::SecretKey::random(&mut rand_core::OsRng);
    let id = Secp256k1Identity::from_private_key(priv_key);

    let delegated_priv_key = k256::SecretKey::random(&mut rand_core::OsRng);
    let delegated_id = Secp256k1Identity::from_private_key(delegated_priv_key);
    let expiry = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        + Duration::from_secs(30 * 24 * 60 * 60);
    let delegation = Delegation {
        pubkey: delegated_id.public_key().unwrap(),
        expiration: expiry.as_nanos() as u64,
        targets: None,
    };
    let del_sig = id.sign_delegation(&delegation).unwrap();
    let delegation_s = SignedDelegation {
        delegation,
        signature: del_sig.signature.unwrap(),
    };
    let sig_pubkey = del_sig.public_key.unwrap();
    assert_eq!(sig_pubkey, id.public_key().unwrap());
    let delegated_id =
        DelegatedIdentity::new(sig_pubkey, Box::new(delegated_id), vec![delegation_s]);

    (id, delegated_id)
}

// Conversion between ic_agent & ic_types
fn into_ic_del(del: Delegation) -> ic_types::messages::Delegation {
    let pubkey = del.pubkey;
    let expiration = ic_types::Time::from_nanos_since_unix_epoch(del.expiration);
    if let Some(targets) = del.targets {
        let targets = targets
            .into_iter()
            .map(|p| ic_types::CanisterId::unchecked_from_principal(ic_types::PrincipalId(p)))
            .collect();
        ic_types::messages::Delegation::new_with_targets(pubkey, expiration, targets)
    } else {
        ic_types::messages::Delegation::new(pubkey, expiration)
    }
}

//  Sign an example message
fn sign_message(id: &impl Identity) -> HttpRequest<SignedIngressContent> {
    let expiry = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        + Duration::from_secs(120);

    let nonce = None;
    let canister_id = Principal::anonymous();
    let sender = id.sender().unwrap();
    let method_name = "test_call".to_string();
    let arg = Encode!(&("hello",)).unwrap();
    let ingress_expiry = expiry.as_nanos() as u64;

    let content = EnvelopeContent::Call {
        nonce: nonce.clone(),
        ingress_expiry,
        sender,
        canister_id,
        method_name: method_name.clone(),
        arg: arg.clone(),
    };
    let sig = id.sign(&content).unwrap();

    // convert ic_agent EnvolopeContent::Call to ic_types HttpRequestEnvelope<HttpCallContent>
    let req_env = HttpRequestEnvelope::<HttpCallContent> {
        content: HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: canister_id.into(),
                method_name,
                arg: arg.into(),
                sender: sender.into(),
                ingress_expiry,
                nonce: nonce.map(Into::into),
            },
        },
        sender_pubkey: id.public_key().map(Into::into),
        sender_sig: sig.signature.map(Into::into),
        sender_delegation: sig.delegations.map(|d| {
            d.into_iter()
                .map(|s| {
                    ic_types::messages::SignedDelegation::new(
                        into_ic_del(s.delegation),
                        s.signature,
                    )
                })
                .collect()
        }),
    };

    req_env.try_into().unwrap()
}

fn verify_msg(msg: &HttpRequest<SignedIngressContent>) -> bool {
    let verifier = IngressMessageVerifier::default();
    verifier.validate_request(msg).is_ok()
}

fn main() {
    let (id, del_id) = generate_delegated_identity();
    let msg = sign_message(&del_id);
    assert_eq!(msg.sender().get().0, id.sender().unwrap());
    assert!(verify_msg(&msg));
    println!("verified!");
}
