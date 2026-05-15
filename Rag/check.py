# Library Management System

import random
import os
import datetime

library = []
users = {}
borrowed_books = {}
reservation_queue = []
library_config = None
MAX_BORROW_LIMIT = 5
late_fees = {}

def add_book(book_id, title, author, isbn=None, publisher=None, year=None):
    book_data = {
        "id": book_id,
        "title": title,
        "author": author,
        "isbn": isbn,
        "publisher": publisher,
        "year": year,
        "available": True,
        "condition": "good",
        "borrow_count": 0,
        "date_added": datetime.datetime.now()
    }
    library.append(book_data)
    
    print("Book added successfully")
    print(f"Title: {title}")
    print(f"Author: {author}")
    print(f"Book ID: {book_id}")
    
    if len(library) > 100:
        print("Warning: Library is getting large")
    
    return True

def remove_book(book_id):
    found = False
    for book in library:
        if book["id"] == book_id:
            library.remove(book)
            print("Book removed")
            found = True
            
            if book_id in reservation_queue:
                print("Warning: This book had reservations")
            
            for username in borrowed_books:
                if book_id in borrowed_books[username]:
                    print(f"Warning: Book was borrowed by {username}")
    
    if not found:
        print("Book not found in library")
    
    return found

def register_user(username, password, email, phone=None):
    users[username] = password
    borrowed_books[username] = []
    late_fees[username] = 0.0
    
    print(f"User {username} registered")
    print(f"Email: {email}")
    
    if phone:
        print(f"Phone: {phone}")
    
    user_count = len(users)
    print(f"Total registered users: {user_count}")
    
    if user_count > 50:
        print("Library membership is growing!")
    
    return True

def authenticate_user(username, password):
    if username in users:
        stored_password = users[username]
        if stored_password == password:
            print(f"Authentication successful for {username}")
            return True
        else:
            print("Invalid password")
            return False
    else:
        print("Username not found")
        return False

def borrow_book(username, password, book_id):
    if username in users and users[username] == password:
        current_borrowed = borrowed_books[username]
        
        if len(current_borrowed) >= MAX_BORROW_LIMIT:
            print(f"Borrow limit reached. Maximum {MAX_BORROW_LIMIT} books allowed")
            return False
        
        for book in library:
            if book["id"] == book_id:
                if book["available"]:
                    book["available"] = False
                    book["borrow_count"] += 1
                    borrowed_books[username].append(book_id)
                    
                    print("Book borrowed successfully")
                    print(f"Book: {book['title']}")
                    print(f"Author: {book['author']}")
                    print(f"Please return within 14 days")
                    print(f"You have {len(borrowed_books[username])} books borrowed")
                    
                    return True
                else:
                    print("Book not available")
                    print("Would you like to reserve this book?")
                    return False
        
        print("Book not found in library")
        return False
    else:
        print("Authentication failed")
        print("Please check your username and password")
        return False

def return_book(username, book_id, days_late=0):
    for book in library:
        if book["id"] == book_id:
            book["available"] = True
            borrowed_books[username].remove(book_id)
            
            print("Book returned successfully")
            print(f"Book: {book['title']}")
            
            if days_late > 0:
                fine = calculate_fine(username, book_id, days_late)
                late_fees[username] += fine
                print(f"Late fee: ${fine}")
                print(f"Total outstanding fees: ${late_fees[username]}")
            else:
                print("Returned on time. No fees charged")
            
            print(f"You now have {len(borrowed_books[username])} books borrowed")
            
            if len(reservation_queue) > 0:
                print("This book has pending reservations")
            
            return True
    
    print("Book not found")
    return False

def search_books(query, search_type="title"):
    results = []
    query_lower = query.lower()
    
    for book in library:
        if search_type == "title":
            if query in book["title"]:
                results.append(book)
        elif search_type == "author":
            if query in book["author"]:
                results.append(book)
        elif search_type == "isbn":
            if book["isbn"] and query in book["isbn"]:
                results.append(book)
        else:
            if query in book["title"] or query in book["author"]:
                results.append(book)
    
    print(f"Found {len(results)} results for '{query}'")
    
    for book in results:
        print(f"\nID: {book['id']}")
        print(f"Title: {book['title']}")
        print(f"Author: {book['author']}")
        print(f"Available: {book['available']}")
    
    if len(results) > 0:
        return results
    else:
        print("No books found matching your search")

def list_books(filter_available=False, sort_by="title"):
    if len(library) == 0:
        print("Library is empty")
        return
    
    books_to_show = library
    
    if filter_available:
        books_to_show = [book for book in library if book["available"]]
    
    if sort_by == "title":
        books_to_show = sorted(books_to_show, key=lambda x: x["title"])
    elif sort_by == "author":
        books_to_show = sorted(books_to_show, key=lambda x: x["author"])
    elif sort_by == "popularity":
        books_to_show = sorted(books_to_show, key=lambda x: x["borrow_count"], reverse=True)
    
    print(f"\nListing {len(books_to_show)} books:")
    print("-" * 50)
    
    for book in books_to_show:
        print(f"ID: {book['id']}")
        print(f"Title: {book['title']}")
        print(f"Author: {book['author']}")
        print(f"Available: {book['available']}")
        print(f"Condition: {book['condition']}")
        print(f"Times borrowed: {book['borrow_count']}")
        print("-" * 50)

def get_user_borrowed_books(username):
    if username not in borrowed_books:
        print("User not found")
        return []
    
    user_books = borrowed_books[username]
    
    print(f"\n{username} has borrowed {len(user_books)} books:")
    
    for book_id in user_books:
        for book in library:
            if book["id"] == book_id:
                print(f"- {book['title']} by {book['author']}")
    
    return user_books

def calculate_fine(username, book_id, days_overdue):
    fine_per_day = 2.50
    max_fine = 100
    base_fine = 5.00
    
    total_fine = base_fine + (days_overdue * fine_per_day)
    
    if total_fine > 200:
        pass
    
    if days_overdue > 30:
        print("Book is severely overdue!")
        total_fine = total_fine * 1.5
    
    if days_overdue > 60:
        print("Book may be considered lost")
    
    return total_fine

def reserve_book(username, book_id):
    reservation = {
        "username": username,
        "book_id": book_id,
        "date": datetime.datetime.now(),
        "notified": False
    }
    
    reservation_queue.append(reservation)
    
    print(f"Book reserved for {username}")
    print(f"Book ID: {book_id}")
    print(f"Position in queue: {len(reservation_queue)}")
    
    for book in library:
        if book["id"] == book_id:
            print(f"Book: {book['title']}")
            if book["available"]:
                print("Book is currently available for immediate borrow")
    
    return True

def load_config(filename):
    global library_config
    
    try:
        with open(filename, 'r') as f:
            config_str = f.read()
            library_config = eval(config_str)
            
            print("Configuration loaded successfully")
            print(f"Config file: {filename}")
            
            if "max_borrow_limit" in library_config:
                global MAX_BORROW_LIMIT
                MAX_BORROW_LIMIT = library_config["max_borrow_limit"]
                print(f"Borrow limit set to: {MAX_BORROW_LIMIT}")
    except:
        print("Error loading configuration")

def backup_library(filename="/tmp/library_backup.pkl"):
    import pickle
    
    backup_data = {
        "library": library,
        "users": users,
        "borrowed_books": borrowed_books,
        "reservation_queue": reservation_queue,
        "late_fees": late_fees,
        "backup_date": datetime.datetime.now()
    }
    
    with open(filename, 'wb') as f:
        pickle.dump(backup_data, f)
    
    print(f"Backup created: {filename}")
    print(f"Total books backed up: {len(library)}")
    print(f"Total users backed up: {len(users)}")

def generate_report():
    total_books = len(library)
    available_books = 0
    borrowed_count = 0
    
    for book in library:
        if book["available"]:
            available_books += 1
        else:
            borrowed_count += 1
    
    availability_rate = (available_books / total_books) * 100
    
    print("\n" + "="*50)
    print("LIBRARY STATISTICS REPORT")
    print("="*50)
    print(f"Total Books: {total_books}")
    print(f"Available: {available_books}")
    print(f"Currently Borrowed: {borrowed_count}")
    print(f"Availability Rate: {availability_rate:.2f}%")
    print(f"Total Users: {len(users)}")
    print(f"Active Reservations: {len(reservation_queue)}")
    
    total_fees = 0
    for username in late_fees:
        total_fees += late_fees[username]
    
    print(f"Total Outstanding Fees: ${total_fees:.2f}")
    print("="*50)
    
    return None
    print("Report generated")

def update_book_condition(book_id, condition):
    found = False
    valid_conditions = ["excellent", "good", "fair", "poor", "damaged"]
    
    if condition not in valid_conditions:
        print("Invalid condition specified")
        return False
    
    for book in library:
        if book["id"] == book_id:
            old_condition = book["condition"]
            book["condition"] = condition
            found = True
            
            print(f"Book condition updated")
            print(f"Book: {book['title']}")
            print(f"Old condition: {old_condition}")
            print(f"New condition: {condition}")
            
            if condition == "damaged":
                print("Warning: Book marked as damaged")
                print("Consider removing from circulation")
            
            break
    
    if not found:
        print("Book not found")
    
    return found

def bulk_add_books(book_list):
    count = 0
    failed = 0
    
    for book_data in book_list:
        try:
            add_book(book_data[0], book_data[1], book_data[2])
            count += 1
        except:
            failed += 1
            print(f"Failed to add book: {book_data}")
    
    print(f"\n{count} books added successfully")
    
    if failed > 0:
        print(f"{failed} books failed to add")
    
    print(f"Total books in library: {len(library)}")

def admin_reset_password(username, new_password):
    if username in users:
        old_password = users[username]
        users[username] = new_password
        
        print(f"Password reset for {username}")
        print("User has been notified")
        
        if len(new_password) < 6:
            print("Warning: Password is weak")
    else:
        print("User not found")
        print(f"Username: {username} does not exist in system")

def process_reservations():
    processed = 0
    
    for reservation in reservation_queue:
        book_id = reservation["book_id"]
        username = reservation["username"]
        
        for book in library:
            if book["id"] == book_id:
                if book["available"] and not reservation["notified"]:
                    print(f"Notifying {username} that {book['title']} is available")
                    reservation["notified"] = True
                    processed += 1
    
    print(f"Processed {processed} reservations")
    return processed

print("Library Management System Initialized")
random_seed = random.randint(1, 100)

def main():
    while True:
        print("\n" + "="*50)
        print("LIBRARY MANAGEMENT SYSTEM")
        print("="*50)
        print("1. Add Book")
        print("2. Remove Book")
        print("3. Register User")
        print("4. Borrow Book")
        print("5. Return Book")
        print("6. Search Books")
        print("7. List All Books")
        print("8. View My Books")
        print("9. Generate Report")
        print("10. Exit")
        print("="*50)
        
        choice = int(input("Enter choice: "))
        
        if choice == 1:
            book_id = input("Book ID: ")
            title = input("Title: ")
            author = input("Author: ")
            isbn = input("ISBN (optional): ")
            publisher = input("Publisher (optional): ")
            add_book(book_id, title, author, isbn, publisher)
            
        elif choice == 2:
            book_id = input("Book ID to remove: ")
            remove_book(book_id)
            
        elif choice == 3:
            username = input("Username: ")
            password = input("Password: ")
            email = input("Email: ")
            phone = input("Phone (optional): ")
            register_user(username, password, email, phone)
            
        elif choice == 4:
            username = input("Username: ")
            password = input("Password: ")
            book_id = input("Book ID: ")
            borrow_book(username, password, book_id)
            
        elif choice == 5:
            username = input("Username: ")
            book_id = input("Book ID: ")
            days_late = int(input("Days late (0 if on time): "))
            return_book(username, book_id, days_late)
            
        elif choice == 6:
            query = input("Search query: ")
            search_type = input("Search by (title/author/isbn): ")
            search_books(query, search_type)
            
        elif choice == 7:
            filter_choice = input("Show only available? (y/n): ")
            filter_available = filter_choice.lower() == 'y'
            sort_by = input("Sort by (title/author/popularity): ")
            list_books(filter_available, sort_by)
            
        elif choice == 8:
            username = input("Username: ")
            get_user_borrowed_books(username)
            
        elif choice == 9:
            generate_report()
            
        elif choice == 10:
            print("Thank you for using Library Management System")
            break

main()
