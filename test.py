import os
import sys
import sqlite3
import hashlib
import requests

# Hardcoded credentials
USERNAME = "admin
PASSWORD = "password123sadfds"  # Storing passwords in plaintext is bad!

# Global variable misuse
global db_connection
db_connection = sqlite3.connect("users.db")
cursor = db_connection.cursor()

# Create an insecure database table
cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);")
db_connection.commit()

def insecure_login():
    """Allows login without input validation, vulnerable to SQL Injection"""
    print("Welcome to the worst login system!")
    user = input("Enter username: ")
    passwd = input("Enter password: ")

    # Vulnerable to SQL Injection
    query = f"SELECT * FROM users WHERE username = '{user}' AND password = '{passwd}';"
    cursor.execute(query)
    result = cursor.fetchone()
    
    if result:
        print("Login successful!")
    else:
        print("Login failed!")

def weak_hashing():
    """Hashes passwords with MD5 (which is insecure)"""
    password = input("Enter a password to hash (insecurely): ")
    hash_object = hashlib.md5(password.encode())  # MD5 is broken and should never be used
    print(f"MD5 Hash: {hash_object.hexdigest()}")

def unsafe_file_handling():
    """Reads a file without checking its existence"""
    filename = input("Enter the file to read: ")
    file = open(filename, "r")  # No exception handling, will crash if file does not exist
    print(file.read())
    file.close()

def remote_code_execution():
    """Executes arbitrary user input (HUGE SECURITY RISK!)"""
    command = input("Enter a shell command to execute: ")
    os.system(command)  # Allows command injection

def fetch_data_from_untrusted_source():
    """Fetches data from an external source without validation"""
    url = input("Enter a URL to fetch data from: ")
    response = requests.get(url)  # No timeout or validation
    print(response.text)

def recursive_stack_overflow(n):
    """Causes a stack overflow with uncontrolled recursion"""
    if n == 0:
        return 1
    return recursive_stack_overflow(n - 1) + 1  # Unoptimized recursion

def unused_variable():
    """Declares but does not use a variable"""
    unused = "I am never used"
    return "Function executed"

if __name__ == "__main__":
    while True:
        print("\n1. Insecure Login\n2. Weak Hashing\n3. Unsafe File Handling\n4. Remote Code Execution\n5. Fetch Data from Untrusted Source\n6. Stack Overflow\n7. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            insecure_login()
        elif choice == "2":
            weak_hashing()
        elif choice == "3":
            unsafe_file_handling()
        elif choice == "4":
            remote_code_execution()
        elif choice == "5":
            fetch_data_from_untrusted_source()
        elif choice == "6":
            recursive_stack_overflow(1000000)  # Will cause a crash
        elif choice == "7":
            print("Exiting...")
            sys.exit()
        else:
            print("Invalid choice!")
