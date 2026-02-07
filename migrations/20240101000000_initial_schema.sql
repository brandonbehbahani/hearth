CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    signature TEXT,
    file_data BLOB,
    file_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT NOT NULL,
    onion_address TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS peer_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    signature TEXT UNIQUE NOT NULL,
    file_data BLOB,
    file_name TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(peer_id) REFERENCES peers(id)
);
