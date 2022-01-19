# CRA_ETL
Automatic ETL script for the Cyber Risk Audit 

This program is designed to extract and normalize data outputted by the CRA ([project found here](https://github.com/sdshook/Audit)). 

# USAGE:
python3 ./etl_process_\*.py -u \[USERNAME] -l \[MYSQL SERVER LOCATION] -n \[DB NAME] -d \[VERBOSE]

# PREP:
1. Install all necessary packages from the requirements.txt file via pip3.
2. Place the script in the same folder as a collection of .zip and .tgz files produced by the CRA2 and CRA_LM scripts linked above.
3. Execute the script with optional parameters via Python3.

# NOTES:
- The 'ss' output is currently incorrectly formatted, and as such has been suspended in the current version of the script. The lines are present, and can be uncommented once the script has been patched.
- No output is available for remotelogons, secsvcstart, syssvcstart, or usbsn. Modules have not been created for these CSVs as the format and future of each CRA output is unclear.
- Updates to include SQLite support are planned.
- Optimization to reduce line count and run time are planned.
