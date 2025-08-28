# vulnerable_oop_app/data_processor.py

class DataProcessor:
    def __init__(self, initial_data: str):
        self.processed_data = initial_data # Taint should propagate here

    def get_data(self) -> str:
        return self.processed_data

    def update_data(self, new_data: str):
        self.processed_data = new_data # Taint should propagate here if new_data is tainted
