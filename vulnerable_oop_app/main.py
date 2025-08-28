# vulnerable_oop_app/main.py
import os
from vulnerable_oop_app.data_processor import DataProcessor

def main():
    user_input = input("Enter something: ") # Source
    
    processor = DataProcessor(user_input) # Taint should propagate to processor.processed_data
    
    # Another way to update tainted data
    another_input = input("Enter more: ") # Another source
    processor.update_data(another_input) # Taint should propagate to processor.processed_data

    # Use the potentially tainted class attribute in a sink
    os.system(f"echo {processor.get_data()}") # Sink - Command Injection

if __name__ == "__main__":
    main()
