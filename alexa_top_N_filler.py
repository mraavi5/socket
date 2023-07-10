import os
import re
import sys
import socket
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Global flag that the tasks check to know if they should exit
RUNNING = True

# Whether to skip rows where the IP address is already filled
SkipFilledEntries = False

# Given a regular expression, list the files that match it, and ask for user input
def selectFile(regex, subdirs=False):
    files = []
    if subdirs:
        for (dirpath, dirnames, filenames) in os.walk('.'):
            for file in filenames:
                path = os.path.join(dirpath, file)
                if path[:2] == '.\\':
                    path = path[2:]
                if bool(re.match(regex, path)):
                    files.append(path)
    else:
        for file in os.listdir(os.curdir):
            if os.path.isfile(file) and bool(re.match(regex, file)):
                files.append(file)
    
    if len(files) == 0:
        print(f'No files were found that match "{regex}"')
        return ''

    print('List of files:')
    for i, file in enumerate(files):
        print(f'  File {i + 1}  -  {file}')

    selection = None
    while selection is None:
        try:
            i = int(input(f'Please select a file (1 to {len(files)}): '))
        except KeyboardInterrupt:
            sys.exit()
        except:
            continue
        if i > 0 and i <= len(files):
            selection = files[i - 1]

    return selection

def fetch_ip(row):
    if row['IP'] and SkipFilledEntries:
        return (row.name, row['IP'])
    try:
        new_ip = ''
        if RUNNING:
            new_ip = socket.gethostbyname(row['Domain'].replace('https://www.', ''))
        return (row.name, new_ip) if new_ip else (row.name, row['IP'])
    except socket.gaierror:
        return (row.name, row['IP'])

file = selectFile(r'^alexa_top_\d+\.csv$', False)

if not file:
    print('No file selected. Exiting...')
    sys.exit()

try:
    df = pd.read_csv(file)
    print("CSV file successfully loaded.")
except Exception as e:
    print("An error occurred while loading the CSV file: ", str(e))
    sys.exit()

df['Domain'] = df['Domain'].apply(lambda x: 'https://www.' + x if not x.startswith('https://www.') else x)

total_rows = len(df)
completed_rows = 0
print_time = time.time()

try:
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(fetch_ip, row) for _, row in df.iterrows()]

        for future in as_completed(futures):
            if not RUNNING:  # exit the loop if we're no longer running
                break
            i, ip = future.result()
            df.at[i, 'IP'] = ip
            completed_rows += 1
            if time.time() - print_time >= 1:  # print at most every second
                print(f'Progress: {completed_rows / total_rows * 100:.2f}%')
                print_time = time.time()  # reset the last print time
except KeyboardInterrupt:
    RUNNING = False
    print("Stopping...")

if RUNNING:  # only write to the CSV file if we were not interrupted
    try:
        df.to_csv(file, index=False)
        print("CSV file successfully updated.")
    except Exception as e:
        print("An error occurred while writing to the CSV file: ", str(e))
