"""MySQL users table + salted hashing (no chat storage).""" 
"""
Database Module - MySQL User Management
Handles user registration, authentication, and credential storage.
"""

import mysql.connector
from mysql.connector import Error
import os
import secrets
from dotenv import load_dotenv
from ..common.utils import sha256_hex, constant_time_compare

# Load environment variables from .env file
load_dotenv()


class DatabaseManager:
    """Manages MySQL database operations for user credentials."""
    
    def __init__(self, host='localhost', database='securechat_db', user='root', password='', port=3306):
        """
        Initialize database connection.
        
        Args:
            host: MySQL server host
            database: Database name
            user: MySQL username
            password: MySQL password
            port: MySQL port
        """
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.connection = None
    
    def connect(self):
        """Establish connection to MySQL database."""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                port=getattr(self, 'port', 3306),
                database=self.database,
                user=self.user,
                password=self.password
            )
            
            if self.connection.is_connected():
                print(f"[✓] Connected to MySQL database '{self.database}'")
                return True
        except Error as e:
            print(f"[✗] Error connecting to MySQL: {e}")
            return False
    
    def disconnect(self):
        """Close database connection."""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("[✓] MySQL connection closed")
    
    def create_tables(self):
        """Create necessary tables if they don't exist."""
        if not self.connection or not self.connection.is_connected():
            print("[✗] Not connected to database")
            return False
        
        try:
            cursor = self.connection.cursor()
            
            # Create users table
            create_table_query = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                salt VARBINARY(16) NOT NULL,
                pwd_hash CHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
            
            cursor.execute(create_table_query)
            self.connection.commit()
            print("[✓] Users table created/verified")
            cursor.close()
            return True
            
        except Error as e:
            print(f"[✗] Error creating tables: {e}")
            return False
    
    def register_user(self, email, username, password):
        """
        Register a new user with salted password hash.
        
        Args:
            email: User email
            username: Username
            password: Plain password (will be hashed)
        
        Returns:
            tuple: (success, message)
        """
        if not self.connection or not self.connection.is_connected():
            return False, "Not connected to database"
        
        try:
            cursor = self.connection.cursor()
            
            # Check if email or username already exists
            check_query = "SELECT email, username FROM users WHERE email = %s OR username = %s"
            cursor.execute(check_query, (email, username))
            result = cursor.fetchone()
            
            if result:
                cursor.close()
                if result[0] == email:
                    return False, "Email already registered"
                else:
                    return False, "Username already taken"
            
            # Generate random 16-byte salt
            salt = secrets.token_bytes(16)
            
            # Compute salted password hash: SHA256(salt || password)
            pwd_hash = self._compute_password_hash(salt, password)
            
            # Insert user
            insert_query = """
            INSERT INTO users (email, username, salt, pwd_hash)
            VALUES (%s, %s, %s, %s)
            """
            cursor.execute(insert_query, (email, username, salt, pwd_hash))
            self.connection.commit()
            
            cursor.close()
            print(f"[✓] User registered: {username} ({email})")
            return True, "Registration successful"
            
        except Error as e:
            print(f"[✗] Error registering user: {e}")
            return False, f"Registration failed: {str(e)}"
    
    def authenticate_user(self, email, password):
        """
        Authenticate user by verifying salted password hash.
        
        Args:
            email: User email
            password: Plain password to verify
        
        Returns:
            tuple: (success, username_or_message)
        """
        if not self.connection or not self.connection.is_connected():
            return False, "Not connected to database"
        
        try:
            cursor = self.connection.cursor()
            
            # Retrieve user data
            query = "SELECT username, salt, pwd_hash FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            
            cursor.close()
            
            if not result:
                return False, "Invalid email or password"
            
            username, salt, stored_hash = result
            
            # Recompute password hash with stored salt
            computed_hash = self._compute_password_hash(salt, password)
            
            # Constant-time comparison to prevent timing attacks
            if constant_time_compare(computed_hash, stored_hash):
                print(f"[✓] User authenticated: {username} ({email})")
                return True, username
            else:
                return False, "Invalid email or password"
            
        except Error as e:
            print(f"[✗] Error authenticating user: {e}")
            return False, f"Authentication failed: {str(e)}"
    
    def _compute_password_hash(self, salt, password):
        """
        Compute salted password hash: hex(SHA256(salt || password))
        
        Args:
            salt: Random salt (bytes)
            password: Plain password (string)
        
        Returns:
            str: Hexadecimal hash (64 characters)
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Concatenate salt and password
        salted_password = salt + password
        
        # Compute SHA-256 using helper function
        return sha256_hex(salted_password)
    
    def get_user_info(self, email):
        """
        Retrieve user information.
        
        Args:
            email: User email
        
        Returns:
            dict or None: User information
        """
        if not self.connection or not self.connection.is_connected():
            return None
        
        try:
            cursor = self.connection.cursor(dictionary=True)
            query = "SELECT id, email, username, created_at FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            cursor.close()
            return result
        except Error as e:
            print(f"[✗] Error retrieving user info: {e}")
            return None
    
    def list_users(self):
        """
        List all registered users (for debugging/testing only).
        
        Returns:
            list: List of user dictionaries
        """
        if not self.connection or not self.connection.is_connected():
            return []
        
        try:
            cursor = self.connection.cursor(dictionary=True)
            query = "SELECT id, email, username, created_at FROM users"
            cursor.execute(query)
            results = cursor.fetchall()
            cursor.close()
            return results
        except Error as e:
            print(f"[✗] Error listing users: {e}")
            return []


def initialize_database():
    """Initialize database and create tables."""
    # Load configuration from environment or use defaults
    db_config = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': int(os.getenv('DB_PORT', 3306)),
        'database': os.getenv('DB_NAME', 'securechat_db'),
        'user': os.getenv('DB_USER', 'root'),
        'password': os.getenv('DB_PASSWORD', '')
    }
    
    db = DatabaseManager(**db_config)
    
    if db.connect():
        db.create_tables()
        
        # List existing users (for verification)
        users = db.list_users()
        if users:
            print(f"\n[*] Existing users in database: {len(users)}")
            for user in users:
                print(f"    - {user['username']} ({user['email']})")
        else:
            print("\n[*] No users in database yet")
        
        db.disconnect()
        return True
    return False


if __name__ == '__main__':
    # Test database initialization
    print("="*60)
    print("Database Initialization")
    print("="*60 + "\n")
    
    if initialize_database():
        print("\n[✓] Database initialization successful!")
    else:
        print("\n[✗] Database initialization failed!")
