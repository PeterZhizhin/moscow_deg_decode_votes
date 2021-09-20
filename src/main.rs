extern crate itertools;

use exonum_sodiumoxide::crypto::box_;
use hex;
use structopt::StructOpt;
use itertools::Itertools;

mod protos;
use protos::choices::Choices;
use protobuf::parse_from_bytes;

#[derive(StructOpt)]
struct Arguments {
    private_key: String,
    public_key: String,
    nonce: String,
    encrypted_message: String,
}

fn main() {
    let arguments = Arguments::from_args();

    let private_key = hex::decode(&arguments.private_key).unwrap();
    let private_key_box = box_::curve25519xsalsa20poly1305::SecretKey::from_slice(&private_key).unwrap();

    let public_key = hex::decode(&arguments.public_key).unwrap();
    let public_key_box = box_::curve25519xsalsa20poly1305::PublicKey::from_slice(&public_key).unwrap();

    let nonce = hex::decode(&arguments.nonce).unwrap();
    let nonce_box = box_::curve25519xsalsa20poly1305::Nonce::from_slice(&nonce).unwrap();

    let encrypted_message = hex::decode(&arguments.encrypted_message).unwrap();
    
    let decrypted_message = box_::open(
        &encrypted_message,
        &nonce_box,
        &public_key_box,
        &private_key_box,
    );

    let decrypted_choices = decrypted_message
                .and_then(|message| {
                    // truncate leading zeros
                    let offset = (((message[0] as u16) << 8) | message[1] as u16) as usize + 2;
                    let original_message = &message[offset..];

                    let choices = parse_from_bytes::<Choices>(&original_message).unwrap();
                    Ok(choices)
                })
                .and_then(|decrypted_choices| {
                    Ok(
                        decrypted_choices
                            .data
                            .into_iter()
                            .filter(|&choice| choice != 0)
                            .collect::<Vec<_>>(),
                    )
                });

    println!("{}", decrypted_choices.unwrap().iter().join(";"));
}
