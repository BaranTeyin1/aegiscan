# vulnerable_app/main.py
import os
from vulnerable_app.helper import process_input

def main():
    user_input = input("Enter something: ") # Source
    
    # Call a function in another module that processes the tainted input
    command_part = process_input(user_input) # Taint should propagate to command_part
    
    # Use the potentially tainted result in a sink
    os.system(command_part) # Sink - Command Injection

if __name__ == "__main__":
    main()
