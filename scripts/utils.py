import os
import json

def export_to_json(data, filename, folder='results'):
    if not os.path.exists(folder):
        os.makedirs(folder)  
    file_path = os.path.join(folder, filename)
    with open(file_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Resultados exportados a {file_path}")

def generate_report(devices, filename):
    try:
        with open(filename, 'w') as report_file:
            report_file.write("Informe de Escaneo de Red\n")
            report_file.write("=" * 30 + "\n\n")
            for device in devices:
                report_file.write(f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device.get('vendor', 'Unknown')}\n")
            print(f"Informe generado exitosamente en {filename}")
    except Exception as e:
        print(f"Error al generar el informe: {e}")

def format_scan_results(devices):
    formatted_results = "Resultados del Escaneo:\n"
    formatted_results += "-" * 30 + "\n"
    for device in devices:
        formatted_results += f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device.get('vendor', 'Unknown')}\n"
    return formatted_results
