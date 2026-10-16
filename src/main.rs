use axum::{
    extract::State,
    Form,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use askama::Template;
use serde::Deserialize;
use sqlx::{sqlite::SqlitePoolOptions, FromRow, SqlitePool};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use arti_client::{TorClient, TorClientConfig};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use futures::StreamExt;
use std::fs;
use tor_rtcompat::PreferredRuntime;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_cell::relaycell::msg::Connected;
use tower_http::services::ServeDir;
use crypto_box::{SecretKey as EncSecretKey, PublicKey as EncPublicKey, ChaChaBox as EncBox};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use rand::RngCore;


// --- Identity Key Management ---
fn get_or_create_identity() -> SigningKey {
    let key_path = "identity.key";
    if std::path::Path::new(key_path).exists() {
        println!("🔑 Loading identity key...");
        let bytes = fs::read(key_path).expect("Failed to read identity.key");
        let bytes: [u8; 32] = bytes.try_into().expect("Invalid key file length");
        SigningKey::from_bytes(&bytes)
    } else {
        println!("🔑 Generating new identity key...");
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        fs::write(key_path, key.to_bytes()).expect("Failed to save identity.key");
        key
    }
}

fn get_or_create_encryption_key() -> EncSecretKey {
    let key_path = "encryption.key";
    if std::path::Path::new(key_path).exists() {
        println!("🔐 Loading encryption key...");
        let bytes = fs::read(key_path).expect("Failed to read encryption.key");
        let bytes: [u8; 32] = bytes.try_into().expect("Invalid key file length");
        EncSecretKey::from(bytes)
    } else {
        println!("🔐 Generating new encryption key...");
        let mut rng = OsRng;
        let key = EncSecretKey::generate(&mut rng);
        fs::write(key_path, key.to_bytes()).expect("Failed to save encryption.key");
        key
    }
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "hearth=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = "sqlite://chat.db?mode=rwc";
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            signature TEXT,
            file_data BLOB,
            file_name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_encrypted BOOLEAN DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT NOT NULL,
            onion_address TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS peer_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            signature TEXT UNIQUE NOT NULL,
            file_data BLOB,
            file_name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_encrypted BOOLEAN DEFAULT 0,
            FOREIGN KEY(peer_id) REFERENCES peers(id)
        );
        "#,
    )
    .execute(&pool)
    .await?;

    // --- Migrations for existing databases ---
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN is_encrypted BOOLEAN DEFAULT 0").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE peers ADD COLUMN public_key TEXT NOT NULL DEFAULT ''").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE peer_messages ADD COLUMN is_encrypted BOOLEAN DEFAULT 0").execute(&pool).await;


    // --- Migrations for existing databases ---
    // SQLite doesn't support ADD COLUMN IF NOT EXISTS, so we try and ignore errors
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN signature TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN file_data BLOB").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE messages ADD COLUMN file_name TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE peer_messages ADD COLUMN signature TEXT").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE peer_messages ADD COLUMN file_data BLOB").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE peer_messages ADD COLUMN file_name TEXT").execute(&pool).await;

    // --- Cleanup invalid peers from previous sessions ---
    let _ = sqlx::query("DELETE FROM peers WHERE onion_address = 'onion_address_123.onion'")
        .execute(&pool)
        .await;

    println!("---------------------------------------");
    println!("🔥 HEARTH: ZEN EDITION v0.1");
    println!("---------------------------------------");
    println!("✅ Database mounted: ./chat.db");

    // --- Identity Key ---
    // --- Identity Key ---
    // --- Identity Key ---
    let signing_key = get_or_create_identity();
    let encryption_key = get_or_create_encryption_key();


    // --- Tor Integration ---
    println!("🧅 Bootstrapping Tor (this may take a while)...");
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await?;
    println!("✅ Tor bootstrapped successfully!");

    // --- Launch Onion Service ---
    let onion_config = OnionServiceConfigBuilder::default()
        .nickname("hearth".parse().unwrap())
        .build()
        .expect("Failed to build onion service config");

    let (onion_service, mut rend_requests) = tor_client.launch_onion_service(onion_config)?;
    
    let onion_address = onion_service
        .onion_name()
        .map(|name| name.to_string())
        .unwrap_or_else(|| "Generating...".to_string());

    println!("---------------------------------------");
    println!("🧅 Onion Service: {}", onion_address);
    println!("---------------------------------------");

    // Background task to handle incoming Tor connections
    let local_addr: SocketAddr = ([127, 0, 0, 1], 3000).into();
    tokio::spawn(async move {
        while let Some(rend_request) = rend_requests.next().await {
            let local_addr = local_addr;
            tokio::spawn(async move {
                if let Ok(mut stream_requests) = rend_request.accept().await {
                    while let Some(stream_request) = stream_requests.next().await {
                        let local_addr = local_addr;
                        tokio::spawn(async move {
                            if let Ok(mut tor_stream) = stream_request.accept(Connected::new_empty()).await {
                                if let Ok(mut local_stream) = tokio::net::TcpStream::connect(local_addr).await {
                                    let _ = tokio::io::copy_bidirectional(&mut tor_stream, &mut local_stream).await;
                                }
                            }
                        });
                    }
                }
            });
        }
    });

    // --- Build App with Onion Address in State ---
    let app_state = Arc::new(AppState {
        pool,
        onion_address: onion_address.clone(),
        tor_client: tor_client.clone(),
        signing_key,
        encryption_key,
    });


    // --- Sync Worker ---
    let sync_state = app_state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            println!("🔄 ZEN SYNC: Starting sync cycle...");
            
            let peers = sqlx::query_as::<_, Peer>("SELECT * FROM peers")
                .fetch_all(&sync_state.pool)
                .await
                .unwrap_or_default();

            for peer in peers {
                let state = sync_state.clone();
                let peer_nick = peer.nickname.clone();
                let peer_onion = peer.onion_address.clone();
                
                tokio::spawn(async move {
                    println!("🔄 SYNC: Connecting to {} ({})...", peer_nick, peer_onion);
                    
                    match state.tor_client.connect((peer_onion.clone(), 80)).await {
                        Ok(mut stream) => {
                            // Fetch messages to gossip (ours + others)
                            let gossip_messages = sqlx::query_as::<_, MessageGossipRow>(
                                r#"
                                SELECT content, timestamp, signature, file_data, file_name, is_encrypted, ? as author_onion 
                                FROM messages 
                                UNION ALL
                                SELECT pm.content, pm.timestamp, pm.signature, pm.file_data, pm.file_name, pm.is_encrypted, p.onion_address as author_onion
                                FROM peer_messages pm
                                JOIN peers p ON pm.peer_id = p.id
                                ORDER BY timestamp DESC LIMIT 50
                                "#
                            )
                            .bind(&state.onion_address)
                            .fetch_all(&state.pool)
                            .await
                            .unwrap_or_default();

                            use base64::prelude::*;
                            let sync_messages: Vec<MessageSync> = gossip_messages.into_iter().map(|m| {
                                MessageSync {
                                    content: m.content,
                                    timestamp: m.timestamp,
                                    signature: m.signature,
                                    file_data_base64: m.file_data.map(|d| BASE64_STANDARD.encode(d)),
                                    file_name: m.file_name,
                                    author_onion: m.author_onion,
                                    is_encrypted: m.is_encrypted,
                                }
                            }).collect();

                            let sync_payload = SyncPayload {
                                onion_address: state.onion_address.clone(),
                                public_key: hex::encode(state.encryption_key.public_key().as_bytes()),
                                messages: sync_messages,
                            };

                            let body = serde_json::to_string(&sync_payload).unwrap();
                            let content_length = body.len();

                            let request = format!(
                                "POST /api/sync HTTP/1.1\r\n\
                                Host: {peer_onion}\r\n\
                                Content-Type: application/json\r\n\
                                Content-Length: {content_length}\r\n\
                                Connection: close\r\n\
                                \r\n\
                                {body}"
                            );

                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            if let Err(e) = stream.write_all(request.as_bytes()).await {
                                println!("❌ SYNC: Failed to write to {}: {}", peer_nick, e);
                                return;
                            }

                            let mut response = String::new();
                            if let Err(e) = stream.read_to_string(&mut response).await {
                                println!("❌ SYNC: Failed to read from {}: {}", peer_nick, e);
                                return;
                            }

                            // Minimal HTTP response "parsing" (just looking for body after \r\n\r\n)
                            if let Some(json_start) = response.find("\r\n\r\n") {
                                let body = &response[json_start + 4..];
                                if let Ok(resp_payload) = serde_json::from_str::<SyncPayload>(body) {
                                    for msg in resp_payload.messages {
                                        // 1. Check if it's our own message (loopback)
                                        if msg.author_onion == state.onion_address {
                                            continue;
                                        }

                                        // 2. Resolve Peer ID (Auto-Discovery)
                                        let author_peer = sqlx::query_as::<_, Peer>("SELECT * FROM peers WHERE onion_address = ?")
                                            .bind(&msg.author_onion)
                                            .fetch_optional(&state.pool)
                                            .await
                                            .unwrap_or(None);

                                        let peer_id = match author_peer {
                                            Some(p) => p.id,
                                            None => {
                                                // Auto-create peer
                                                let short_nick = format!("{}...", &msg.author_onion[0..12]);
                                                let res = sqlx::query("INSERT INTO peers (nickname, onion_address) VALUES (?, ?)")
                                                    .bind(&short_nick)
                                                    .bind(&msg.author_onion)
                                                    .execute(&state.pool)
                                                    .await;
                                                
                                                match res {
                                                    Ok(r) => r.last_insert_rowid(),
                                                    Err(_) => continue, // Skip if failed to create peer
                                                }
                                            }
                                        };

                                        let file_data = msg.file_data_base64.as_ref()
                                            .and_then(|b64| BASE64_STANDARD.decode(b64).ok());

                                        let _ = sqlx::query(
                                            "INSERT OR IGNORE INTO peer_messages (peer_id, content, signature, timestamp, file_data, file_name) VALUES (?, ?, ?, ?, ?, ?)"
                                        )
                                        .bind(peer_id)
                                        .bind(msg.content)
                                        .bind(msg.signature)
                                        .bind(msg.timestamp)
                                        .bind(file_data)
                                        .bind(msg.file_name)
                                        .execute(&state.pool)
                                        .await;
                                    }
                                    println!("✅ SYNC: Successfully synced with {}", peer_nick);
                                }
                            }
                        }
                        Err(e) => {
                            println!("❌ SYNC: Could not reach {}: {}", peer_nick, e);
                        }
                    }
                });
            }
        }
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/messages", get(get_messages))
        .route("/send", post(send_message))
        .route("/connect", post(connect_peer))
        .route("/peer-list", get(get_peer_list))
        .route("/api/sync", post(sync_messages))
        .nest_service("/assets", ServeDir::new("assets"))
        .with_state(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("✅ UI Live at: http://{}", addr);
    println!("---------------------------------------");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("---------------------------------------");
    println!("💤 HEARTH is resting...");
    println!("---------------------------------------");
}

struct AppState {
    pool: SqlitePool,
    onion_address: String,
    tor_client: TorClient<PreferredRuntime>,
    signing_key: SigningKey,
    encryption_key: EncSecretKey,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    onion_address: String,
    peers: Vec<Peer>,
}

#[derive(Template)]
#[template(path = "peer_list.html")]
struct PeerListTemplate {
    peers: Vec<Peer>,
}

#[derive(Template)]
#[template(path = "message_list.html")]
struct MessageListTemplate {
    messages: Vec<Message>,
}

#[derive(FromRow, serde::Serialize, serde::Deserialize, Clone)]
struct Message {
    id: Option<i64>,
    content: String,
    timestamp: String,
    sender_name: String,
    signature: String,
    file_data: Option<Vec<u8>>,
    file_name: Option<String>,
    #[sqlx(default)]
    is_encrypted: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedMessage {
    ciphertext: String,
    nonce: String,
    ephemeral_pk: String,
    key_nonce: String,
    recipients: std::collections::HashMap<String, String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct InnerMessage {
    content: String,
    file_name: Option<String>,
    file_data: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct MessageGossipRow {
    content: String,
    timestamp: String,
    signature: String,
    file_data: Option<Vec<u8>>,
    file_name: Option<String>,
    #[sqlx(default)]
    is_encrypted: bool,
    author_onion: String,
}

impl Message {
    fn file_data_base64_helper(&self) -> String {
        use base64::prelude::*;
        self.file_data.as_ref()
            .map(|data| BASE64_STANDARD.encode(data))
            .unwrap_or_default()
    }
}

#[derive(FromRow, serde::Serialize, Clone)]
struct Peer {
    id: i64,
    nickname: String,
    onion_address: String,
    #[sqlx(default)]
    public_key: String,
}

#[derive(Deserialize)]
struct CreateMessage {
    content: String,
}

#[derive(Deserialize)]
struct ConnectPeer {
    nickname: String,
    onion_address: String,
}

async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let peers = sqlx::query_as::<_, Peer>("SELECT * FROM peers")
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();

    IndexTemplate {
        onion_address: state.onion_address.clone(),
        peers,
    }
}

async fn get_peer_list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let peers = sqlx::query_as::<_, Peer>("SELECT * FROM peers")
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();

    PeerListTemplate { peers }
}

async fn connect_peer(
    State(state): State<Arc<AppState>>,
    Form(payload): Form<ConnectPeer>,
) -> impl IntoResponse {
    let onion_addr = payload.onion_address.trim();
    let nick = payload.nickname.trim();

    let is_valid_onion = is_valid_onion_address(onion_addr);
    
    if !nick.is_empty() && is_valid_onion {
        let _ = sqlx::query("INSERT OR IGNORE INTO peers (nickname, onion_address) VALUES (?, ?)")
            .bind(nick)
            .bind(onion_addr)
            .execute(&state.pool)
            .await;
    } else if !is_valid_onion && !nick.is_empty() {
        println!("⚠️ VALIDATION: Rejected invalid onion address: {}", onion_addr);
    }
    
    get_peer_list(State(state)).await
}

/// Tor v3 onion address check: exactly 56 base32 characters (`a-z`, `2-7`,
/// either case) followed by `.onion`.
fn is_valid_onion_address(addr: &str) -> bool {
    match addr.strip_suffix(".onion") {
        Some(host) => {
            host.len() == 56
                && host
                    .bytes()
                    .all(|b| matches!(b.to_ascii_lowercase(), b'a'..=b'z' | b'2'..=b'7'))
        }
        None => false,
    }
}

async fn delete_peer(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> impl IntoResponse {
    let _ = sqlx::query("DELETE FROM peers WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await;
    
    get_peer_list(State(state)).await
}

async fn get_messages(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let messages = sqlx::query_as::<_, Message>(
        r#"
        SELECT id, content, timestamp, 'YOU' as sender_name, signature, file_data, file_name, is_encrypted FROM messages
        UNION ALL
        SELECT pm.id, pm.content, pm.timestamp, p.nickname as sender_name, pm.signature, pm.file_data, pm.file_name, pm.is_encrypted
        FROM peer_messages pm
        JOIN peers p ON pm.peer_id = p.id
        ORDER BY timestamp ASC LIMIT 50
        "#,
    )
    .fetch_all(&state.pool)
    .await;

    let mut decrypted_messages = Vec::new();
    if let Ok(msgs) = messages {
        use base64::prelude::*;
        
        for mut msg in msgs {
            if msg.is_encrypted {
                let decrypted_opt = (|| {
                     let enc_msg: EncryptedMessage = serde_json::from_str(&msg.content).ok()?;
                     let key_nonce_bytes = BASE64_STANDARD.decode(&enc_msg.key_nonce).ok()?;
                     
                     // Handle potential nonce length issues or panic
                     if key_nonce_bytes.len() != 24 { return None; }
                     let key_nonce_arr: [u8; 24] = key_nonce_bytes.try_into().ok()?;
                     let key_nonce = crypto_box::Nonce::from(key_nonce_arr);
                     
                     let eph_pk_bytes = hex::decode(&enc_msg.ephemeral_pk).ok()?;
                     let eph_pk_arr: [u8; 32] = eph_pk_bytes.try_into().ok()?;
                     let eph_pk = EncPublicKey::from(eph_pk_arr);

                     if let Some(enc_key_b64) = enc_msg.recipients.get(&state.onion_address) {
                         let enc_key = BASE64_STANDARD.decode(enc_key_b64).ok()?;
                         
                         // Decrypt Key
                         let my_box = EncBox::new(&eph_pk, &state.encryption_key);
                         let key_bytes_vec = my_box.decrypt(&key_nonce, enc_key.as_slice()).ok()?;
                         let key_bytes = ChaChaKey::from_slice(&key_bytes_vec);

                         // Decrypt Payload
                         let nonce_bytes = BASE64_STANDARD.decode(&enc_msg.nonce).ok()?;
                         let nonce = ChaChaNonce::from_slice(&nonce_bytes);
                         let ciphertext = BASE64_STANDARD.decode(&enc_msg.ciphertext).ok()?;

                         let cipher = ChaCha20Poly1305::new(key_bytes);
                         let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
                         
                         let inner: InnerMessage = serde_json::from_slice(&plaintext).ok()?;
                         Some(inner)
                     } else {
                         None
                     }
                })();

                if let Some(inner) = decrypted_opt {
                    msg.content = inner.content;
                    msg.file_name = inner.file_name;
                    msg.file_data = inner.file_data;
                    msg.is_encrypted = true; // Keep true to show lock icon
                    // Let's prepend a lock icon to clean content to indicate it WAS encrypted
                    // msg.content = format!("🔒 {}", inner.content); 
                } else {
                    msg.content = "🔒 Encrypted Message".to_string();
                }
            }
            decrypted_messages.push(msg);
        }
    }

    MessageListTemplate { messages: decrypted_messages }
}

async fn send_message(
    State(state): State<Arc<AppState>>,
    mut multipart: axum::extract::Multipart,
) -> impl IntoResponse {
    let mut content = String::new();
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        if name == "content" {
            content = field.text().await.unwrap_or_default();
        } else if name == "attachment" {
            let fname = field.file_name().unwrap_or_default().to_string();
            if !fname.is_empty() {
                let bytes = field.bytes().await.unwrap_or_default();
                if bytes.len() <= 512000 { // 500KB
                    file_name = Some(fname);
                    file_data = Some(bytes.to_vec());
                } else {
                    println!("⚠️ UPLOAD: File too large (> 500KB)");
                }
            }
        }
    }

    if !content.trim().is_empty() || file_data.is_some() {
        use base64::prelude::*;
        use ed25519_dalek::Signer;

        // 1. Prepare Inner Message
        let inner = InnerMessage {
            content: content.clone(),
            file_name: file_name.clone(),
            file_data: file_data.clone(),
        };
        let inner_json = serde_json::to_vec(&inner).unwrap();

        // 2. Symmetric Encryption Check
        // We always encrypt now, since keys are established.
        // Generate Payload Key (32 bytes)
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let payload_key = ChaChaKey::from_slice(&key_bytes);
        
        // Generate Payload Nonce (12 bytes for ChaCha20Poly1305)
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let payload_nonce = ChaChaNonce::from_slice(&nonce_bytes);

        // Encrypt Payload
        let cipher = ChaCha20Poly1305::new(payload_key);
        let ciphertext_payload = cipher.encrypt(payload_nonce, inner_json.as_ref()).expect("Encryption failed");

        // 3. Key Encapsulation (Multi-Recipient)
        let mut recipients_map = std::collections::HashMap::new();
        
        // Generate Ephemeral Keypair (once for this message)
        let ephemeral_sk = EncSecretKey::generate(&mut OsRng);
        let ephemeral_pk = ephemeral_sk.public_key();
        
        // Generate Key Encapsulation Nonce (24 bytes for XSalsa20/Box)
        let mut key_enc_nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut key_enc_nonce_bytes);
        let key_enc_nonce = crypto_box::Nonce::from(key_enc_nonce_bytes);

        // Fetch Recipients (All Peers + Self)
        let mut targets = sqlx::query_as::<_, Peer>("SELECT * FROM peers").fetch_all(&state.pool).await.unwrap_or_default();
        targets.push(Peer { 
            id: 0, 
            nickname: "ME".to_string(), 
            onion_address: state.onion_address.clone(), 
            public_key: hex::encode(state.encryption_key.public_key().as_bytes()) 
        });

        for peer in targets {
            if peer.public_key.is_empty() { continue; }
            if let Ok(pk_bytes) = hex::decode(&peer.public_key) {
                if let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) {
                    let peer_pk = EncPublicKey::from(pk_arr);
                    // Encrypt the SYMMETRIC KEY 'key_bytes' using Peer's Public Key + Ephemeral SK
                    let peer_box = EncBox::new(&peer_pk, &ephemeral_sk);
                    if let Ok(encrypted_key) = peer_box.encrypt(&key_enc_nonce, key_bytes.as_slice()) {
                         recipients_map.insert(peer.onion_address, BASE64_STANDARD.encode(encrypted_key));
                    }
                }
            }
        }

        let encrypted_msg = EncryptedMessage {
            ciphertext: BASE64_STANDARD.encode(ciphertext_payload),
            nonce: BASE64_STANDARD.encode(nonce_bytes),
            ephemeral_pk: hex::encode(ephemeral_pk.as_bytes()),
            key_nonce: BASE64_STANDARD.encode(key_enc_nonce_bytes),
            recipients: recipients_map,
        };

        let final_content = serde_json::to_string(&encrypted_msg).unwrap();

        // Sign the encrypted payload
        let signature = state.signing_key.sign(final_content.as_bytes()).to_bytes();
        let sig_hex = hex::encode(signature);
        
        let result = sqlx::query("INSERT INTO messages (content, signature, file_data, file_name, is_encrypted) VALUES (?, ?, ?, ?, ?)")
            .bind(final_content)
            .bind(sig_hex)
            .bind(None::<Vec<u8>>) // Clear plaintext metadata
            .bind(None::<String>)
            .bind(true)
            .execute(&state.pool)
            .await;

        match result {
            Ok(_) => println!("✅ MESSAGE: Sent encrypted message"),
            Err(e) => println!("❌ MESSAGE: Failed to save: {}", e),
        }
    }
    ""
}

#[derive(serde::Deserialize, serde::Serialize)]
struct MessageSync {
    content: String,
    timestamp: String,
    signature: String,
    file_data_base64: Option<String>,
    file_name: Option<String>,
    author_onion: String,
    is_encrypted: bool,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct SyncPayload {
    onion_address: String,
    public_key: String, 
    messages: Vec<MessageSync>,
}

async fn sync_messages(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<SyncPayload>,
) -> impl IntoResponse {
    use base64::prelude::*;

    // 0. Update Peer Public Key
    let _ = sqlx::query("UPDATE peers SET public_key = ? WHERE onion_address = ?")
        .bind(&payload.public_key)
        .bind(&payload.onion_address)
        .execute(&state.pool)
        .await;

    // 1. Find or create peer


    // Accept messages regardless of who sent the payload (GOSSIP)
    for msg in payload.messages {
        // 1. Check if it's our own message (loopback)
        if msg.author_onion == state.onion_address {
             continue;
        }

        // 2. Resolve Peer ID (Auto-Discovery)
        let author_peer = sqlx::query_as::<_, Peer>("SELECT * FROM peers WHERE onion_address = ?")
            .bind(&msg.author_onion)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);

        let peer_id = match author_peer {
            Some(p) => p.id,
            None => {
                // Auto-create peer
                let short_nick = format!("{}...", &msg.author_onion[0..12]);
                let res = sqlx::query("INSERT INTO peers (nickname, onion_address) VALUES (?, ?)")
                    .bind(&short_nick)
                    .bind(&msg.author_onion)
                    .execute(&state.pool)
                    .await;
                
                match res {
                    Ok(r) => r.last_insert_rowid(),
                    Err(_) => continue, // Skip if failed to create peer
                }
            }
        };

        let file_data = msg.file_data_base64.as_ref()
            .and_then(|b64| BASE64_STANDARD.decode(b64).ok());

        let _ = sqlx::query(
            "INSERT OR IGNORE INTO peer_messages (peer_id, content, signature, timestamp, file_data, file_name, is_encrypted) VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(peer_id)
        .bind(msg.content)
        .bind(msg.signature)
        .bind(msg.timestamp)
        .bind(file_data)
        .bind(msg.file_name)
        .bind(msg.is_encrypted)
        .execute(&state.pool)
        .await;
    }

    // 2. Return our messages (GOSSIP: Send ours AND theirs)
    let gossip_messages = sqlx::query_as::<_, MessageGossipRow>(
        r#"
        SELECT content, timestamp, signature, file_data, file_name, is_encrypted, ? as author_onion 
        FROM messages 
        UNION ALL
        SELECT pm.content, pm.timestamp, pm.signature, pm.file_data, pm.file_name, pm.is_encrypted, p.onion_address as author_onion
        FROM peer_messages pm
        JOIN peers p ON pm.peer_id = p.id
        ORDER BY timestamp DESC LIMIT 50
        "#
    )
    .bind(&state.onion_address)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let sync_messages: Vec<MessageSync> = gossip_messages.into_iter().map(|m| {
        MessageSync {
            content: m.content,
            timestamp: m.timestamp,
            signature: m.signature,
            file_data_base64: m.file_data.map(|d| BASE64_STANDARD.encode(d)),
            file_name: m.file_name,
            author_onion: m.author_onion,
            is_encrypted: m.is_encrypted,
        }
    }).collect();

    let response_payload = SyncPayload {
        onion_address: state.onion_address.clone(),
        public_key: hex::encode(state.encryption_key.public_key().as_bytes()),
        messages: sync_messages,
    };

    axum::Json(response_payload)
}

#[cfg(test)]
mod tests {
    use super::is_valid_onion_address;

    // 56 base32 chars, the length of a real Tor v3 onion host.
    const HOST: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd";

    #[test]
    fn accepts_v3_address() {
        assert_eq!(HOST.len(), 56);
        assert!(is_valid_onion_address(&format!("{HOST}.onion")));
        assert!(is_valid_onion_address(&format!("{}.onion", HOST.to_uppercase())));
    }

    #[test]
    fn rejects_wrong_length_or_suffix() {
        assert!(!is_valid_onion_address(""));
        assert!(!is_valid_onion_address(".onion"));
        assert!(!is_valid_onion_address(HOST));
        assert!(!is_valid_onion_address(&format!("{}.onion", &HOST[..16]))); // v2-length
        assert!(!is_valid_onion_address(&format!("{HOST}a.onion")));
        assert!(!is_valid_onion_address(&format!("{HOST}.com")));
    }

    #[test]
    fn rejects_non_base32_characters() {
        // '0', '1', '8', '9' are not base32; neither are symbols or spaces.
        for bad in ['0', '1', '8', '9', '!', ' ', '/', '.', '-'] {
            let mut host: String = HOST[..55].to_string();
            host.push(bad);
            assert!(!is_valid_onion_address(&format!("{host}.onion")), "accepted {bad:?}");
        }
    }
}
