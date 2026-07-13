import sqlite3
import os

def initialize_system_database():
    database_name = "secure_share.db"
    
    # Remove existing instance to guarantee clean schema validation if needed
    if os.path.exists(database_name):
        print("[*] Refreshing database environment...")
        
    connection = sqlite3.connect(database_name)
    cursor = connection.cursor()
    
    # 1. Create Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # 2. Create Encrypted Files Log Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT NOT NULL,
            recipient_email TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_email) REFERENCES users(email)
        )
    ''')
    
    connection.commit()
    connection.close()
    print("[+] Database schemas successfully compiled and verified.")

if __name__ == "__main__":
    initialize_system_database()