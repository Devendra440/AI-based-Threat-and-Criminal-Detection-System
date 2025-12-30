import sqlite3
import os

# Database Path
db_path = 'data/security_system.db'
env_path = '.env'

# User Details
username = "user49856"
email = "user49856@protonmail.com"
password = "6o6fku77"

# 1. Update Database
try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        print(f"User {username} already exists. Updating credentials...")
        cursor.execute('''
            UPDATE users 
            SET password = ?, receiver_email = ?, sender_email = ?, sender_password = ?
            WHERE username = ?
        ''', (password, email, email, password, username))
    else:
        print(f"Creating new user {username}...")
        cursor.execute('''
            INSERT INTO users (username, password, receiver_email, sender_email, sender_password)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password, email, email, password))
    
    conn.commit()
    conn.close()
    print("Database updated successfully.")
except Exception as e:
    print(f"Database error: {e}")

# 2. Update .env file
try:
    lines = []
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            lines = f.readlines()
    
    new_lines = []
    keys_updated = []
    
    # Update existing keys
    for line in lines:
        if line.startswith('SENDER_EMAIL='):
            new_lines.append(f'SENDER_EMAIL={email}\n')
            keys_updated.append('SENDER_EMAIL')
        elif line.startswith('SENDER_PASSWORD='):
            new_lines.append(f'SENDER_PASSWORD={password}\n')
            keys_updated.append('SENDER_PASSWORD')
        elif line.startswith('RECEIVER_EMAIL='):
            new_lines.append(f'RECEIVER_EMAIL={email}\n')
            keys_updated.append('RECEIVER_EMAIL')
        else:
            new_lines.append(line)
            
    # Add missing keys
    if 'SENDER_EMAIL' not in keys_updated:
        new_lines.append(f'\nSENDER_EMAIL={email}\n')
    if 'SENDER_PASSWORD' not in keys_updated:
        new_lines.append(f'SENDER_PASSWORD={password}\n')
    if 'RECEIVER_EMAIL' not in keys_updated:
        new_lines.append(f'RECEIVER_EMAIL={email}\n')
        
    with open(env_path, 'w') as f:
        f.writelines(new_lines)
    print(".env file updated successfully.")
    
except Exception as e:
    print(f".env error: {e}")
