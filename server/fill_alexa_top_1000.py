import socket
import pandas as pd

# Load the CSV file into a DataFrame
try:
    df = pd.read_csv('alexa_top_1000.csv')
    print("CSV file successfully loaded.")
except Exception as e:
    print("An error occurred while loading the CSV file: ", str(e))
    exit()

# Iterate over each row in the DataFrame
for i, row in df.iterrows():
    print(f"Processing row {i+1}...")
    
    # Check if the domain starts with 'https://www.'
    if not row['Domain'].startswith('https://www.'):
        # Prepend 'https://www.' to the domain
        df.at[i, 'Domain'] = 'https://www.' + row['Domain']
        print(f"Updated domain to: {df.at[i, 'Domain']}")

    # Fetch the IP address for the domain
    try:
        ip_address = socket.gethostbyname(row['Domain'].replace('https://www.', ''))
        print(f"IP address fetched: {ip_address}")
    except socket.gaierror:
        ip_address = ''
        print(f"Could not fetch IP address for domain: {df.at[i, 'Domain']}")
        
    # Update the IP address in the DataFrame
    df.at[i, 'IP'] = ip_address

# Write the updated DataFrame back to the CSV file
try:
    df.to_csv('alexa_top_1000.csv', index=False)
    print("CSV file successfully updated.")
except Exception as e:
    print("An error occurred while writing to the CSV file: ", str(e))
