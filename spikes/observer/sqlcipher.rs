use std::error::Error;

use rusqlite::{Connection, Error as SqlError, ErrorCode, OpenFlags};
use tempfile::NamedTempFile;

fn open_for_read(database: &NamedTempFile, key: Option<&str>) -> rusqlite::Result<String> {
    let connection =
        Connection::open_with_flags(database.path(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    if let Some(key) = key {
        connection.pragma_update(None, "key", key)?;
    }
    connection.query_row("SELECT body FROM messages", [], |row| row.get(0))
}

fn main() -> Result<(), Box<dyn Error>> {
    let database = NamedTempFile::new()?;
    let fixture_key = "howl-sqlcipher-probe-key";
    let fixture_body = "howl-sqlcipher-probe-message";

    let connection = Connection::open(database.path())?;
    connection.pragma_update(None, "key", fixture_key)?;
    let version: String =
        connection.pragma_query_value(None, "cipher_version", |row| row.get(0))?;
    let provider: String =
        connection.pragma_query_value(None, "cipher_provider", |row| row.get(0))?;
    let provider_version: String =
        connection.pragma_query_value(None, "cipher_provider_version", |row| row.get(0))?;
    connection.execute("CREATE TABLE messages (body TEXT NOT NULL)", [])?;
    connection.execute("INSERT INTO messages VALUES (?1)", [fixture_body])?;
    drop(connection);

    let encrypted = std::fs::read(database.path())?;
    assert!(!encrypted.starts_with(b"SQLite format 3\0"));
    assert!(
        !encrypted
            .windows(fixture_body.len())
            .any(|window| window == fixture_body.as_bytes())
    );
    assert_eq!(open_for_read(&database, Some(fixture_key))?, fixture_body);

    for key in [None, Some("howl-sqlcipher-wrong-key")] {
        assert!(matches!(
            open_for_read(&database, key),
            Err(SqlError::SqliteFailure(error, _)) if error.code == ErrorCode::NotADatabase
        ));
    }
    println!("SQLCipher {version}, {provider} {provider_version}: encrypted reopen passed");
    Ok(())
}
