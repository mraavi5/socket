import os
import pandas as pd
import socket

# Send commands to the terminal
def terminal(cmd):
    print(cmd)
    return os.popen(cmd).read()

# Load the CSV file into a DataFrame
try:
    df = pd.read_csv('alexa_top_1000.csv')
    print("CSV file successfully loaded.")
except Exception as e:
    print("An error occurred while loading the CSV file: ", str(e))
    exit()

print('Clearing current Redis database...')
terminal('cd redis_researcher; ./run.sh')
terminal('cd redis_researcher; ./run_clear_all.sh')

# Iterate over each row in the DataFrame
for i, row in df.iterrows():
    print(f"Processing row {i+1}...")

    # Check if the row has a valid IP address
    if row['IP'] != '':
        # Call the shell script with the domain and IP address
        try:
            domain = row['Domain']
            if domain.startswith('https://www.'): domain = domain[12:]
            command = f'cd redis_researcher; ./run_write.sh {domain} {row["IP"]}'
            response = terminal(command).strip()
            if response != 'OK':
                print('Redis could not be written to')
                break
        except Exception as e:
            print(f"An error occurred while running the command: {str(e)}")
    else:
        print(f"Skipping row {i+1} due to invalid IP.")
