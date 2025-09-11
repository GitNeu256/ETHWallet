use ethers::core::rand::thread_rng;
use ethers::core::types::{Address, U256};
use ethers::signers::{LocalWallet, Signer};
use ethers::prelude::*;
use ethers::utils;
use std::convert::TryFrom;
use std::fs;
use std::str::FromStr;
use std::io::{self, Write};
use std::process::Command;

use qrcode::QrCode;
use qrcode::render::unicode;

use sodiumoxide::crypto::secretbox;
use scrypt::{Params, scrypt};
use rpassword::read_password;
use zeroize::Zeroize;
use serde::{Serialize, Deserialize};

const KEY_FILE: &str = "data.dat";

#[derive(Serialize, Deserialize)]
struct WalletData {
    private_key: String,
    address: Address,
}

fn encrypt_key(private_key: &str, password: &str) -> Vec<u8> {
    let key = derive_key(password);
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(private_key.as_bytes(), &nonce, &key);

    let mut encrypted_data = nonce.0.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);
    encrypted_data
}

fn derive_key(password: &str) -> secretbox::Key {
    let params = Params::recommended(); // Используем новое название структуры
    let mut derived_key = [0u8; 32];

    scrypt(password.as_bytes(), b"wallet_salt", &params, &mut derived_key).unwrap();
    let key = secretbox::Key::from_slice(&derived_key).unwrap();

    derived_key.zeroize(); // Удаляем из памяти
    key
}

/// Расшифровывает приватный ключ
fn decrypt_key(encrypted_data: &[u8], password: &str) -> Option<String> {
    let key = derive_key(password);

    if encrypted_data.len() < secretbox::NONCEBYTES {
        return None;
    }

    let nonce = secretbox::Nonce::from_slice(&encrypted_data[..secretbox::NONCEBYTES]).unwrap();
    let ciphertext = &encrypted_data[secretbox::NONCEBYTES..];

    match secretbox::open(ciphertext, &nonce, &key) {
        Ok(decrypted) => Some(String::from_utf8_lossy(&decrypted).to_string()),
        Err(_) => None,
    }
}

fn load_wallet() -> Option<WalletData> {
    use std::fs;

    // Проверяем, существует ли файл
    if !std::path::Path::new(KEY_FILE).exists() {
        println!("Wallet file not found.");
        return None;
    }

    // Читаем содержимое файла
    let encrypted_key = match fs::read(KEY_FILE) {
        Ok(data) => data,
        Err(e) => {
            println!("Wallet reading error: {}", e);
            return None;
        }
    };

    // Запрашиваем пароль с циклом повторных попыток
    let mut password;
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 3; // Максимальное количество попыток ввода пароля

    // Цикл до правильного ввода пароля или достижения максимального количества попыток
    loop {
        password = get_password("Enter the password to decrypt the key: ");
        
        // Расшифровываем ключ
        let private_key = decrypt_key(&encrypted_key, &password); // Это Option, а не Result

        // Обрабатываем Option
        match private_key {
            Some(key) => {
                // Пробуем создать кошелек из приватного ключа
                match key.parse::<LocalWallet>() {
                    Ok(wallet) => {
                        // Возвращаем кошелек и приватный ключ
                        return Some(WalletData {
                            private_key: key,
                            address: wallet.address(),
                        });
                    }
                    Err(e) => {
                        println!("Error creating a wallet from a private key: {}", e);
                        return None;
                    }
                }
            }
            None => {
                // Пароль неверный
                println!("Invalid password. Try again.");
                attempts += 1;

                // Если превышено количество попыток
                if attempts >= MAX_ATTEMPTS {
                    println!("The number of attempts has been exceeded. Exit.");
                    return None;
                }
            }
        }
    }
}

/// Функция очистки экрана
fn clear_screen() {
    if cfg!(target_os = "windows") {
        Command::new("cmd").args(&["/C", "cls"]).status().unwrap();
    } else {
        Command::new("clear").status().unwrap();
    }
}

/// Запрашивает пароль у пользователя
fn get_password(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    
    let password = read_password().expect("Error reading password.");
    
    password.trim().to_string()
}

/// Генерирует новый кошелек
fn generate_new_account() -> (String, Address) {
    let wallet = LocalWallet::new(&mut thread_rng());
    let private_key = hex::encode(wallet.signer().to_bytes()); // Получаем приватный ключ корректно
    let address = wallet.address();

    let password = get_password("Enter the password to encrypt the key: ");
    let encrypted_key = encrypt_key(&private_key, &password);

    fs::write(KEY_FILE, encrypted_key).expect("Error saving key.");

    println!("The wallet has been created. Address: {}", address);
    (private_key, address)
}

/// Импорт существующего кошелька
fn import_existing_account() -> Option<(String, Address)> {
    print!("Enter your private key:");
    io::stdout().flush().unwrap();

    let mut private_key = String::new();
    io::stdin().read_line(&mut private_key).expect("Reading error.");
    let private_key = private_key.trim().to_string();

    match private_key.parse::<LocalWallet>() {
        Ok(wallet) => {
            let address = wallet.address();
            let password = get_password("Enter the password to encrypt the key: ");
            let encrypted_key = encrypt_key(&private_key, &password);

            fs::write(KEY_FILE, encrypted_key).expect("Error saving key.");

            println!("The wallet has been imported. Address: {}", address);
            Some((private_key, address))
        }
        Err(_) => {
            println!("Error: Invalid private key.");
            None
        }
    }
}

/// Проверка баланса
async fn check_balance(address: Address) -> eyre::Result<()> {
    let provider = Provider::<Http>::try_from("https://mainnet.ethereumpow.org")?;
    let balance = provider.get_balance(address, None).await?;

    println!("Wallet: {:?}", address);
    println!("Balance: {} ETHW", ethers::utils::format_ether(balance));

    let code = QrCode::new(&address).unwrap();

    let image = code
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    println!("{}", image);

    Ok(())
}

async fn send_transaction(
    private_key: &str,
    to_address: &str,
    value: f64
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider::<Http>::try_from("https://mainnet.ethereumpow.org")?;
    let chain_id = provider.get_chainid().await?;
    // Парсим приватный ключ
    let wallet: LocalWallet = private_key.parse::<LocalWallet>()?
        .with_chain_id(chain_id.as_u64());

    let client = SignerMiddleware::new(provider, wallet.clone());

    // Конвертация ETHW в Wei
    let amount = ethers::utils::parse_ether(value)?;

    // Создаём транзакцию
    let tx = TransactionRequest::new()
        .to(Address::from_str(to_address)?)
        .value(U256::from(utils::parse_ether(amount)?));

    // Подписываем и отправляем
    let pending_tx = client.send_transaction(tx, None).await?;
    let tx_hash = pending_tx.tx_hash();

    println!("Transaction sent! TX Hash: {:?}", tx_hash);

    Ok(())
}

fn menu() -> u32 {
    println!("========================");
    println!("ETHWallet");
    println!("========================");
    println!("1. View wallet details.");
    println!("2. Check balance.");
    println!("3. Send tokens.");
    println!("4. Exit.");
    println!("========================");
    print!("Select an option: ");
    
    io::stdout().flush().unwrap();

    let mut choice = String::new();
    io::stdin().read_line(&mut choice).expect("Error reading input.");

    match choice.trim().parse::<u32>() {
        Ok(num) => num,
        Err(_) => {
            println!("Invalid input! Try again.");
            0
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet_data = loop {
        if let Some(wallet) = load_wallet() {
            break wallet;
        } else {
            println!("Wallet file not found.");
            println!("1. Create a new wallet.");
            println!("2. Import existing.");
            println!("3. Exit.");

            let mut choice = String::new();
            io::stdin().read_line(&mut choice).expect("Input error.");

            match choice.trim() {
                "1" => {
                    let (private_key, address) = generate_new_account();
                    break WalletData { private_key, address: address };
                }
                "2" => {
                    if let Some((private_key, address)) = import_existing_account() {
                        break WalletData { private_key, address: address };
                    }
                }
                "3" => {
                    println!("Exit...");
                    return Ok(());
                }
                _ => println!("Invalid input, please try again."),
            }
        }
    };

    loop {
        let choice = menu();

        match choice {
            1 => {
                clear_screen();
                println!("Address: {}", utils::to_checksum(&wallet_data.address, None));
                println!("Private key: {}", wallet_data.private_key);
                let code = QrCode::new(&wallet_data.private_key).unwrap();

                let image = code
                    .render::<unicode::Dense1x2>()
                    .quiet_zone(true)
                    .build();
                println!("{}", image);
            }
            2 => {
                clear_screen();
                check_balance(wallet_data.address).await?;
            }
            3 => {
                clear_screen();
                println!("Enter recipient's address:");
                let mut to_address = String::new();
                io::stdin().read_line(&mut to_address).expect("Input error.");

                println!("Enter the amount to send (ETHW):");
                let mut amount = String::new();
                io::stdin().read_line(&mut amount).expect("Input error.");

                let amount: f64 = amount.trim().parse().expect("Incorrect amount.");
                
                send_transaction(&wallet_data.private_key, to_address.trim(), amount).await?;
            }
            4 => {
                println!("Exit...");
                break;
            }
            _ => println!("Invalid input, please try again."),
        }
    }

    Ok(())
}