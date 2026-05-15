import sqlite3
import pickle
import hashlib
import os
from datetime import datetime

class LibraryManagement:
    def __init__(self, db_name="library.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.setup_database()
        self.current_user = None
    
    def setup_database(self):
        # Security Issue #1: SQL Injection vulnerability in table creation
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users
                             (id INTEGER PRIMARY KEY, username TEXT, 
                              password TEXT, role TEXT)''')
        
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS books
                             (id INTEGER PRIMARY KEY, title TEXT, 
                              author TEXT, isbn TEXT, available INTEGER)''')
        
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS transactions
                             (id INTEGER PRIMARY KEY, user_id INTEGER, 
                              book_id INTEGER, action TEXT, date TEXT)''')
        self.conn.commit()
    
    def register_user(self, username, password, role="user"):
        # Security Issue #2: Weak password hashing (MD5)
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        
        # Security Issue #3: SQL Injection in INSERT
        query = f"INSERT INTO users (username, password, role) VALUES ('{username}', '{hashed_password}', '{role}')"
        self.cursor.execute(query)
        self.conn.commit()
        return "User registered successfully"
    
    def login_user(self, username, password):
        # Security Issue #4: SQL Injection in SELECT
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed_password}'"
        self.cursor.execute(query)
        user = self.cursor.fetchone()
        
        if user:
            self.current_user = {"id": user[0], "username": user[1], "role": user[3]}
            return f"Welcome {username}!"
        return "Invalid credentials"
    
    def add_book(self, title, author, isbn):
        if not self.current_user or self.current_user["role"] != "admin":
            return "Unauthorized access"
        
        # Security Issue #5: No input validation/sanitization
        query = f"INSERT INTO books (title, author, isbn, available) VALUES ('{title}', '{author}', '{isbn}', 1)"
        self.cursor.execute(query)
        self.conn.commit()
        return "Book added successfully"
    
    def search_books(self, search_term):
        # SQL Injection in search functionality
        query = f"SELECT * FROM books WHERE title LIKE '%{search_term}%' OR author LIKE '%{search_term}%'"
        self.cursor.execute(query)
        return self.cursor.fetchall()
    
    def save_user_session(self, filename):
        # Security Issue #6: Insecure Deserialization
        session_data = {
            "user": self.current_user,
            "timestamp": datetime.now()
        }
        with open(filename, 'wb') as f:
            pickle.dump(session_data, f)
        return "Session saved"
    
    def load_user_session(self, filename):
        # Pickle deserialization vulnerability
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                session_data = pickle.load(f)
            self.current_user = session_data["user"]
            return "Session restored"
        return "Session file not found"
    
    def get_user_info(self, user_id):
        # More SQL injection opportunities
        query = f"SELECT username, role FROM users WHERE id={user_id}"
        self.cursor.execute(query)
        return self.cursor.fetchone()
    
    def delete_book(self, book_id):
        if not self.current_user or self.current_user["role"] != "admin":
            return "Unauthorized"
        
        query = f"DELETE FROM books WHERE id={book_id}"
        self.cursor.execute(query)
        self.conn.commit()
        return "Book deleted"

def demonstration_usage():
    library = LibraryManagement()
    
    # Normal usage
    print(library.register_user("alice", "password123", "admin"))
    print(library.login_user("alice", "password123"))
    print(library.add_book("Python Security", "John Doe", "1234567890"))
    print(library.search_books("Python"))
    
    # Save and load session
    library.save_user_session("session.pkl")
    library.load_user_session("session.pkl")

if __name__ == "__main__":
    demonstration_usage()