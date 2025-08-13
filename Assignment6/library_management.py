class Book:
    def __init__(self, title, author, ISBN, available=True):
        self.title = title
        self.author = author
        self.ISBN = ISBN
        self.available = available

class Library:
    def __init__(self):
        self.books = []

    def add_book(self, book):
        self.books.append(book)
        print(f"Added '{book.title}' to the library.")

    def remove_book(self, isbn):
        for book in self.books:
            if book.ISBN == isbn:  # Fixed case
                self.books.remove(book)
                print(f"Removed '{book.title}' from the library.")
                return
        print("Book not found.")

    def lend_book(self, isbn):
        for book in self.books:
            if book.ISBN == isbn:
                if book.available:
                    book.available = False
                    print(f"Lent out '{book.title}'.")
                else:
                    print(f"'{book.title}' is already lent out.")
                return
        print("Book not found.")

    def return_book(self, isbn):
        for book in self.books:
            if book.ISBN == isbn:  # Fixed case
                if not book.available:
                    book.available = True
                    print(f"Returned '{book.title}'.")
                else:
                    print(f"'{book.title}' was not lent out.")
                return
        print("Book not found.")

    def list_books(self):
        if not self.books:
            print("No books in the library.")
            return
        for book in self.books:
            status = "Available" if book.available else "Lent out"
            print(f"{book.title} by {book.author} (ISBN: {book.ISBN}) - {status}")


# --- Demo ---
library = Library()

b1 = Book("1984", "George Orwell", "12345")
b2 = Book("The Great Gatsby", "F. Scott Fitzgerald", "54321")

library.add_book(b1)
library.add_book(b2)

library.list_books()
library.lend_book("12345")
library.list_books()
library.return_book("12345")
library.remove_book("54321")
library.list_books()
