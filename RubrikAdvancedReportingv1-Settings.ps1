########################################################################################################################
# Written by: Joshua Stenhouse joshuastenhouse@gmail.com
################################################
# Description:
# This script allows you to configure the global settings for all the RubrikAutoTicketing scripts. 
# If you want to override any specific variable for a particular script, then copy it into the script after the section marked # Global settings import. I.E to change the BusinessSLAInHours
################################################ 
# Requirements:
# - Run PowerShell as administrator with command "Set-ExecutionPolcity unrestricted" on the host running the script
################################################
# Legal Disclaimer:
# This script is written by Joshua Stenhouse is not supported under any support program or service. 
# All scripts are provided AS IS without warranty of any kind. 
# The author further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
# The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
# In no event shall its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if the author has been advised of the possibility of such damages.
################################################
# Configure the variables below
################################################
$RubrikCluster = "Rubrik IP or FQDN"
# Configure your Business SLA in hours here, only used by the Business SLA script. If any VM doesn't have a snapshot within the last x hours specified, it will be indicated as NotMeetingSLA.
$BusinessSLAInHours = 24
# Specify the exact name of any SLAs you want to EXCLUDE from the reports in the below comma seperated variable
$SLADomainsToExclude = "SLA's to Exclude from Report"
# Configure on-demand backups to rectify objects NotMeetingSLA automatically here. WARNING: this will auto trigger an on demand snapshot to the existing SLA if an object is deemed out of SLA
$EnableAutoOnDemandSnapshots = $FALSE
# CSV output settings
$EnableCSVOutput = $TRUE
$CSVOutputDirectory = "C:\temp"
# Config the email settings
$EnableEmail = $TRUE
# If email is enabled, a report of everything is sent to this address
$ReportEmailTo = "darren.swift@email.com"
# A single email containing all the objects NotMeetingSLA will be sent, if none exist nothing is sent, use your IT ticketing system to address here to auto create tickets on failures
$FailureEmailTo = "darren.swift@email.com"
# SMTP server settings
$SMTPSSLEnabled = $TRUE
$SMTPAuthRequired = $TRUE
$SMTPServer = "smtp.gmail.com"
$SMTPPort = "587"
# Email address sent from
$EmailFrom = "darrentswift@gmail.com"
# Email subjects
$Date = Get-Date 
$ReportEmailSubject = "Rubrik VM Backup Report " + $Date.ToString("MM-dd-yyyy")
$FailureEmailSubject = "Rubrik VM Backups NotMeetingSLA " + $Date.ToString("MM-dd-yyyy")
# HTML Color codes used for email report
$HTMLColorSuccess = "#008000"
$HTMLColorWarning = "#FFA500"
$HTMLColorFailure = "#FF0000"
################################################
# Nothing to edit below, implemented functions to parse large JSON objects in PowerShell 5.x or below
################################################
# Example taken from Florian Feldhaus on https://stackoverflow.com/questions/16854057/convertfrom-json-max-length/27125027
# Function 1
function ParseItem($jsonItem) 
{
    if($jsonItem.PSObject.TypeNames -match 'Array') 
    {
        return ParseJsonArray($jsonItem)
    }
    elseif($jsonItem.PSObject.TypeNames -match 'Dictionary') 
    {
        return ParseJsonObject([HashTable]$jsonItem)
    }
    else 
    {
        return $jsonItem
    }
}
# Function 2
function ParseJsonObject($jsonObj) 
{
    $result = New-Object -TypeName PSCustomObject
    foreach ($key in $jsonObj.Keys) 
    {
        $item = $jsonObj[$key]
        if ($item) 
        {
            $parsedItem = ParseItem $item
        }
        else 
        {
            $parsedItem = $null
        }
        $result | Add-Member -MemberType NoteProperty -Name $key -Value $parsedItem
    }
    return $result
}
# Function 3
function ParseJsonArray($jsonArray) 
{
    $result = @()
    $jsonArray | ForEach-Object -Process {
        $result += , (ParseItem $_)
    }
    return $result
}
# Function 4
function ParseJsonString($json) 
{
    $config = $javaScriptSerializer.DeserializeObject($json)
    return ParseJsonObject($config)
}
################################
# End of script
################################