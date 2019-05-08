# Rubrik-Custom-Reporting
Rubrik custom reporting

#01 - Copy all scripts in this repo to a single directory

#01 - Sart with RubrikAdvancedReportingv1-Settings.ps1 and edit the commented sections marked "Configure Variables Below"

#02 - Run Create Rubrik Credentials.ps1 and enter credentials on input this will save your credentials in to an .xml so they do not have to be entered or placed in plain text

#3 - Run SMTP Credentials.ps1 and enter credentials on input this will save your credentials in to an .xml so they do not have to be entered or placed in plain text

#4 - Now all configuration is done, it is the choice of the user the frequency this report will run (can be scheduled via task scheduler) to run. Ensure $ScriptDirectory is correct and run the script. 

This script will output 2 x CSV's one being a backup summary / report and the other being a failure report 

This script will output 2 x email's one being a backup summary / rpeort and the other being a failure report 
