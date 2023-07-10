import socket
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def fetch_ip(row):
    try:
        new_ip = socket.gethostbyname(row['Domain'].replace('https://www.', ''))
        return (row.name, new_ip) if new_ip else (row.name, row['IP'])
    except socket.gaierror:
        return (row.name, row['IP'])

try:
    df = pd.read_csv('alexa_top_1000.csv')
    print("CSV file successfully loaded.")
except Exception as e:
    print("An error occurred while loading the CSV file: ", str(e))
    exit()

df['Domain'] = df['Domain'].apply(lambda x: 'https://www.' + x if not x.startswith('https://www.') else x)

total_rows = len(df)
completed_rows = 0

with ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(fetch_ip, row) for _, row in df.iterrows()]

    for future in as_completed(futures):
        i, ip = future.result()
        df.at[i, 'IP'] = ip
        completed_rows += 1
        print(f'Progress: {completed_rows / total_rows * 100:.2f}%')

try:
    df.to_csv('alexa_top_1000.csv', index=False)
    print("CSV file successfully updated.")
except Exception as e:
    print("An error occurred while writing to the CSV file: ", str(e))
