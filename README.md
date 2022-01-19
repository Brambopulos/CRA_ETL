# CRA_ETL
Automatic ETL script for the Cyber Risk Audit 

This program is designed to extract and normalize data outputted by the CRA ([project found here](https://github.com/sdshook/Audit)). 

# USAGE:
python3 ./etl_process_\*.py -u \[USERNAME] -l \[MYSQL SERVER LOCATION] -n \[DB NAME] -d \[VERBOSE]

# PREP:
1. Install all necessary packages from the requirements.txt file via pip3.
2. Place the script in the same folder as a collection of .zip and .tgz files produced by the CRA2 and CRA_LM scripts linked above.
3. Execute the script with optional parameters via Python3.
