$RubrikCredentials = Get-Credential -Message "Enter Rubrik login credentials"
$RubrikCredentials | EXPORT-CLIXML "C:\ScriptDirectory\RubrikCredentials.xml"