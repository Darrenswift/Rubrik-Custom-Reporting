$SMTPCredentials = Get-Credential -Message "Enter SMTP Authentication credentials"
$SMTPCredentials | EXPORT-CLIXML "C:\ScriptDirectory\SMTPCredentials.xml"