use sqlx::{sqlite::{SqlitePool, SqliteConnectOptions, SqliteJournalMode}, Pool, Sqlite, migrate::MigrateDatabase};
use std::str::FromStr;
use std::path::Path;
use tokio::fs;

pub type DbPool = Pool<Sqlite>;

pub async fn init_db() -> Result<DbPool, Box<dyn std::error::Error>> {
    let db_url = "sqlite://chat.db";

    // 1. Ensure the file exists (Create if missing)
    if !Sqlite::database_exists(db_url).await.unwrap_or(false) {
        println!("Database not found. Creating chat.db...");
        Sqlite::create_database(db_url).await?;
    } else {
        println!("Database exists.");
    }

    // 2. Connect
    let options = SqliteConnectOptions::from_str(db_url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal); 

    let pool = SqlitePool::connect_with(options).await?;

    // 3. Run Migrations (Embedded)
    println!("Running migrations...");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await?;
    
    println!("Database initialized.");

    Ok(pool)
}
