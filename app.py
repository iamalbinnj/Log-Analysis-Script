import re
import csv

from collections import Counter

logFile="./sample.log"

def countIpAddress(file_path):
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' # ip address regex from https://learn.microsoft.com/en-us/answers/questions/1633102/regex-validation-for-ip-address-fields-in-azure-wo

    with open(file_path,'r') as file:
        log_content = file.read()
    
    ip_address = re.findall(ip_pattern, log_content)

    ip_count = Counter(ip_address)

    if ip_count: return ip_count 
    else: return "No Ip Address"


def frequent_endpoint(file_path):
    endpoint_pattern = r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (/[\w\-./]*)'

    with open(file_path,'r') as file:
        log_content = file.read()
    
    enpoint = re.findall(endpoint_pattern,log_content)

    endpoint_count = Counter(enpoint)

    if endpoint_count: return endpoint_count
    else: return "No Frequent Endpoint"
    

def detect_supicious_activity(file_path, failed_login=10):

    failed_login_pattern = r'(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b).*(401|Invalid credentials)'
    
    with open (file_path,'r') as file:
        log_content_line = file.readlines()
    
    failed_login_list = []
    for line in log_content_line:
        match = re.search(failed_login_pattern,line)
        if match:
            failed_login_list.append(match.group('ip'))
    
    failed_login_count = Counter(failed_login_list)

    suspicious_ip_address = {ip: count for ip, count in failed_login_count.items() if count > failed_login}

    if suspicious_ip_address: return suspicious_ip_address
    else: return "No Suspicious Ip Address"

def save_csv(ip_count, endpoint_count, suspicious_ip, output="log_analysis_results.csv"):
    try:
        with open(output, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Count Requests per IP Address
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_count.items():
                writer.writerow([ip, count])
            writer.writerow([])

            # Most Frequently Accessed Endpoint
            writer.writerow(["Most Frequently Accessed Endpoint"])
            if endpoint_count:
                most_frequent = endpoint_count.most_common(1)[0]
                writer.writerow([f"{most_frequent[0]} (Accessed {most_frequent[1]} times)"])
            writer.writerow([])

            # Detect Suspicious Activity
            writer.writerow(["IP Address", "Failed Login Attempts"])
            if suspicious_ip:
                for ip, count in suspicious_ip.items():
                    writer.writerow([ip, count])

        print(f"saved to {output}")
    except FileNotFoundError as e:
        print(f"Error: File not found: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    try:
        ip_count = countIpAddress(logFile)
        frequent = frequent_endpoint(logFile)
        supicious_activity = detect_supicious_activity(logFile, failed_login=1)
        
        save_csv(ip_count,frequent,supicious_activity)
    except FileNotFoundError:
        print(f"Error: The file {logFile} does not exist.")