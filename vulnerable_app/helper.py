# vulnerable_app/helper.py

def process_input(data: str) -> str:
    """
    Processes the input data. In a real scenario, this might involve
    some sanitization or transformation, but for this vulnerability,
    it simply returns the data, propagating the taint.
    """
    # Simulate some processing without proper sanitization
    processed_data = f"echo {data}"
    return processed_data
