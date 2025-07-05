extern crate secp256k1;
use secp256k1::{Secp256k1, Message, SecretKey};
use secp256k1::rand::rngs::OsRng;
use sha256::digest;
use bs58::encode;
use std::str;
use crypto::digest::Digest;
use hex;
use reqwest;
use serde_json::Value;
use base64::Engine;
use base64::engine::general_purpose;

const PRIV_KEY:&str = "6ed468dc51c9e909ce2b27bcf07fcbe6d6e8e541348bd61687ccefbeaa983810";
const PUB_KEY:&str = "029f8bc9b6910ea1b8e3350780905fbd8408c600d887f51e3cdeb2385d0a4bcc47";
const BIT_ADDRESS:&str = "myCChgp8HLSmES1CxScU2REiphQ9o5VJLE";

const MINER_FEE:u64 = 400;



#[tokio::main]
async fn main() {
    send("myCChgp8HLSmES1CxScU2REiphQ9o5VJLE",1000000).await;
}
fn check_address(receiver_address: &str) -> bool{
    if receiver_address.chars().nth(0).unwrap() != 'm' && receiver_address.chars().nth(0).unwrap() != 'n'{
        return false
    }
    let decoded = bs58::decode(receiver_address).into_vec();
    let bytes = match &decoded{
        Ok(_) => decoded.unwrap(),
        Err(_) => return false, 
    };
    let user_checksum = bytes[(bytes.len()-4)..].to_vec();
    let to_hash = bytes[..(bytes.len()-4)].to_vec();
    let real_checksum = hex::decode(digest(&hex::decode(digest(&to_hash)).unwrap())).unwrap()[0..4].to_vec();
    return user_checksum == real_checksum
}

// amit davagenerire bitcoin address 
fn generate_bitcoin_address() -> (String,String,String) {
    let secp = Secp256k1::new();
    let (tmp_private_key,tmp_public_key) = secp.generate_keypair(&mut OsRng);
    let mut public_key_bytes = hex::decode(tmp_public_key.to_string()).unwrap();
    public_key_bytes = hex::decode(digest(public_key_bytes)).unwrap();
    let mut ripehash = crypto::ripemd160::Ripemd160::new();
    ripehash.input(&public_key_bytes);
    let  payload = hex::decode(ripehash.result_str()).unwrap();
    let tmp_pref = "6F";
    let mut pref = hex::decode(tmp_pref).unwrap();
    pref.extend(&payload);
    let  checksum = &hex::decode(digest(&hex::decode(digest(&pref)).unwrap())).unwrap()[0..4];
    pref.extend(checksum.to_vec());
    let encoded = encode(pref).into_string();
    return (tmp_public_key.to_string(),tmp_private_key.display_secret().to_string(),encoded);
}




//------------------------------------------------------------------------------


async fn get_utxos() -> Vec<Value>{
    let user_pass = b"rezga:rezga";
    let encoded: String = general_purpose::STANDARD.encode(user_pass);
    println!("encoded: {}",encoded);
    let token = format!("Basic {encoded}");
    println!("token: {}",token);
    let client = reqwest::Client::new();
    let res = client
        .post("http://127.0.0.1:18332")
        .body(format!(r#"{{"jsonrpc":"1.0","method":"listunspent","params":[2,999999,["{BIT_ADDRESS}"]]}}"#))
        .header("content-type", "application/json")
        .header("Authorization", token).send().await.unwrap();
        
    let text: String = res.text().await.unwrap();
    let v:Value = serde_json::from_str(&text[..]).unwrap(); 
    let result_array:&Value = &v["result"];
    let vec = result_array.as_array().unwrap();
    return vec.to_owned();
}

// returns number of inputs to spend and the sum of that inputs (-1 if insufficient)
fn get_lower_bound_amount(utxos:&Vec<Value>, satoshis:u64) -> (i32,u64){
    let mut sum: f64 = 0.0;
    let mut ind = -1;
    for item in utxos{
        let amount:f64 = item["amount"].as_f64().unwrap();
        sum+=amount;
        if (sum * 1e8) as u64 >= satoshis {
            return (ind+1,(sum*1e8) as u64);
        }
        ind+= 1;
    }
    println!("sum is: {}",sum);
    return (-1,0);

}


fn get_version() -> String{
    return "02000000".to_owned();
}
fn get_input_num(num: i32) -> String{
    return format!("{:02x}",num); 
}
fn get_v_out(vout:u32) -> String{
    let res = hex::encode(vout.to_le_bytes());
    return res;
}
fn tx_id_to_little_endian(tx_id:String) -> String{
    let mut tmp_bytes = hex::decode(&tx_id).unwrap();
    tmp_bytes.reverse();
    return hex::encode(tmp_bytes);  
}
fn address_to_pubhash(address:String) -> String{
    let  decoded = bs58::decode(address).into_vec().unwrap();
    let x = hex::encode(&decoded[1..(decoded.len()-4)]);
    return x;
}
// ----------------------------------------------------------------

struct Transaction{
    version:String,
    input_num:String,
    output_num:String,
    inputs:Vec<String>,
    outputs:Vec<String>,
    lock_time:String,
    hash_code:String,
}

impl Transaction{
    fn new() -> Transaction{
        Transaction { 
            version: ("".to_owned()),
            input_num: ("".to_owned()), 
            inputs: (Vec::new()),
            outputs: (Vec::new()), 
            output_num: ("".to_owned()),
            lock_time: ("".to_owned()),
            hash_code: ("".to_owned()),
        }
    }
    fn set_version(&mut self, new_version:String){
        self.version = new_version;
    }
    fn set_input_num(&mut self,new_input_num:String){
        self.input_num = new_input_num;
    }
    fn set_output_num(&mut self,new_output_num:String){
        self.output_num = new_output_num;
    }
    fn set_lock_time(&mut self, new_lock_time:String){
        self.lock_time = new_lock_time;
    }
    fn set_hash_code(&mut self, new_hash_code:String){
        self.hash_code = new_hash_code;
    }
    fn add_input(&mut self, new_input:String){
        self.inputs.push(new_input);
    }
    fn clear_inputs(&mut self){
        self.inputs.clear();
    }
    fn add_output(&mut self, new_output:String){
        self.outputs.push(new_output);
    }
    fn get_string(&mut self) -> String{
        let mut transaction:String = String::from("");
        transaction += self.version.as_str();
        transaction += self.input_num.as_str();
        for input in &self.inputs{
            transaction += input.as_str();
        }
        transaction += self.output_num.as_str();
        for output in &self.outputs{
            transaction += output.as_str();
        }
        transaction += self.lock_time.as_str();
        transaction += self.hash_code.as_str();
        return transaction
    }
}


// preparing inputs for signing, replaces input_ind-th input with scriptPubkey and others with 00  
fn add_inputs_for_signing(transaction:& mut Transaction,max_len:usize,utxos:&Vec<Value>, input_ind:usize){
    transaction.clear_inputs();
    for i in 0..max_len{
        let mut input:String = String::from("");
        input += tx_id_to_little_endian(utxos[i]["txid"].as_str().unwrap().to_owned()).as_str();
        input += get_v_out(utxos[i]["vout"].as_u64().unwrap() as u32).as_str();
        if i == input_ind{
            let pubkey_script = utxos[i]["scriptPubKey"].as_str().unwrap();
            let pubkey_script_size = format!("{:02x}",pubkey_script.len() / 2);
            input+=pubkey_script_size.as_str();
            input+=pubkey_script;
        }
        else{
            input += "00";
        }
        input += "ffffffff";
        transaction.add_input(input);
    }
}


fn create_output(amount:u64,address:String) -> String{
    let mut to_send_output = "".to_owned();
    to_send_output += hex::encode(amount.to_le_bytes()).as_str();
    to_send_output += "19";
    to_send_output += "76a914";
    to_send_output += address_to_pubhash(address.to_owned()).as_str();
    to_send_output += "88ac";
    return to_send_output
}

// for every prepared transaction for signing, signs and fills in the vector of signatures
fn create_signatures(max_len:usize,transaction:&mut Transaction,utxos:&Vec<Value>,signatures:&mut Vec<String>){
    let secp = Secp256k1::new();
    for i in 0..max_len{
        add_inputs_for_signing(transaction, max_len, &utxos, i);
        let mut final_signature = "".to_owned();
        let message = Message::from_digest_slice(hex::decode(digest(hex::decode(digest(hex::decode(transaction.get_string()).unwrap())).unwrap())).unwrap().as_slice()).unwrap();
        let mut signature = secp.sign_ecdsa(&message, &SecretKey::from_slice(hex::decode(PRIV_KEY).unwrap().as_slice()).unwrap()).to_string();
        signature+="01";
        let sig_size = &format!("{:x}",signature.len() / 2)[..];
        let pub_size = "21";
        let whole_size = format!("{:x}", (sig_size.len()+pub_size.len()+PUB_KEY.len()+signature.len()) / 2);
        final_signature += whole_size.as_str();
        final_signature += sig_size;
        final_signature += signature.as_str();
        final_signature += pub_size;
        final_signature += PUB_KEY;
        signatures.push(final_signature);
    }
}
// for every input, fills signature size and signature
fn add_signatures(transaction:&mut Transaction, signatures:&Vec<String>,max_len:usize,utxos:&Vec<Value>){
    transaction.clear_inputs();
    for i in 0..max_len{
        let mut input:String = String::from("");
        input += tx_id_to_little_endian(utxos[i]["txid"].as_str().unwrap().to_owned()).as_str();
        input += get_v_out(utxos[i]["vout"].as_u64().unwrap() as u32).as_str();
        input += signatures[i].as_str();
        input += "ffffffff";
        transaction.add_input(input);
    }
}
fn address_to_pubhas(address:String) -> String{
    let  decoded = bs58::decode(address).into_vec().unwrap();
    let x = hex::encode(&decoded[1..(decoded.len()-4)]);
    return x;
}
// this code sends the request to call sendrawtransaction
async fn finalize_send(transaction:String){
    let user_pass = b"rezga:rezga";
    let encoded: String = general_purpose::STANDARD.encode(user_pass);
    let token = format!("Basic {encoded}");
    let client = reqwest::Client::new();
    let mut req = r#"{"method":"sendrawtransaction","params":[""#.to_owned();
    req+=transaction.as_str();
    req+="\"]}";
     let res = client
     .post("http://127.0.0.1:18332")
     .body(req)
     .header("content-type", "application/json")
     .header("Authorization", token).send().await.unwrap();
    println!("result is: {}",res.status().is_success());
}


async fn send(receiver_address: &str, amount_satoshis: u64) {
   let res = check_address(receiver_address);
   if res == false{
       println!("invalid address");
   }
    let utxos:Vec<Value> = get_utxos().await;
    let (lower_bound,to_spend)= get_lower_bound_amount(&utxos,amount_satoshis);
    if lower_bound == -1{
        println!("here");
        return;
    }

    let max_len:usize = lower_bound as usize + 1; // number of inputs

    let mut transaction = Transaction::new();
    transaction.set_version(get_version());
    transaction.set_input_num(get_input_num(lower_bound+1));
    transaction.set_output_num("02".to_owned());

    let to_send_output = create_output(amount_satoshis,receiver_address.to_owned());
    let to_receive_output = create_output(to_spend-amount_satoshis-MINER_FEE,BIT_ADDRESS.to_owned());

    transaction.add_output(to_send_output);
    transaction.add_output(to_receive_output);
    transaction.set_lock_time("00000000".to_owned());
    transaction.set_hash_code("01000000".to_owned());

    let mut signatures:Vec<String> = Vec::new();
    create_signatures(max_len,&mut transaction,&utxos,&mut signatures);
    add_signatures(& mut transaction,&signatures,max_len,&utxos);

    let mut final_transaction = transaction.get_string();
    final_transaction = final_transaction[..(final_transaction.len()-8)].to_owned();

    println!("transaction: {}", final_transaction);
    finalize_send(final_transaction).await;
}
