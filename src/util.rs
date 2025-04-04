use soft_aes::aes::aes_dec_ecb;
use soft_aes::aes::aes_enc_ecb;

// I know aes ecb is bad, i copy pasted this from my hi3 private server, lol
static AES_KEY: [u8; 32] = [0; 32]; // put your own aes key here
// also put your own secret key here
pub const SECRET_KEY: &str = "ABC1234"; // this is so only my dad can use the website

#[inline(always)]
pub fn encrypt_ecb(data: &str) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted = aes_enc_ecb(data.as_bytes(), &AES_KEY, Some("PKCS7"))?;
    Ok(rbase64::encode(&encrypted))
}

#[inline(always)]
pub fn decrypt_ecb(data: &str) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted_bytes = rbase64::decode(data)?;
    let decrypted = aes_dec_ecb(&encrypted_bytes, &AES_KEY, Some("PKCS7"))?;
    Ok(String::from_utf8(decrypted)?)
}
