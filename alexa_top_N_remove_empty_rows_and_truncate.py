import os
import re
import sys
import pandas as pd

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

# Remove rows with a blank 'IP' field
df = df[df['IP'].notna() & (df['IP'] != '')]

# Get the maximum number of entries from the file name and truncate if necessary
num = int(re.search(r'\d+', file).group())
df = df[:num]

try:
    df.to_csv(file, index=False)
    print("CSV file successfully updated.")
except Exception as e:
    print("An error occurred while writing to the CSV file: ", str(e))
