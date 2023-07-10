import pandas as pd

# Load the CSV file into a DataFrame
try:
    df = pd.read_csv('alexa_top_1000.csv')
    print("CSV file successfully loaded.")
except Exception as e:
    print("An error occurred while loading the CSV file: ", str(e))
    exit()

# Remove rows with a blank 'IP' field
df = df[df['IP'].notna() & (df['IP'] != '')]

# Write the updated DataFrame back to the CSV file
try:
    df.to_csv('alexa_top_1000.csv', index=False)
    print("CSV file successfully updated.")
except Exception as e:
    print("An error occurred while writing to the CSV file: ", str(e))

