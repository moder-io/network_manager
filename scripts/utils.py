import os
import json

def export_to_json(data, filename, folder='results'):
    if not os.path.exists(folder):
        os.makedirs(folder)  
    file_path = os.path.join(folder, filename)
    with open(file_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Resultados exportados a {file_path}")