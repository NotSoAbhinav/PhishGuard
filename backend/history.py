history = []

def add_history(entry):
    history.append(entry)

def get_history():
    return history[-10:]

def clear_history():
    global history
    history.clear()