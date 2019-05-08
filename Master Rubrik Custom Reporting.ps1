########################################################################################################################
# Written by: Darren Swift darren.swift@rubrik.com
########################################################################################################################
# Description:
# This script automatically verifies each VM snapshot is within the Business SLA you define. 
# Ensure the ScriptDirectory is configured to the correct location as all the settings are derived from RubrikAutoTicketingv1-Settings.ps1 in it.
# On first run the script will prompt for Rubrik credentials and store them securely for subsequent runs
# It can be configured with the settings script to automatically email reports, auto remediate objects with on-demand snapshots, and create helpdesk tickets with a consolidated failure report.
################################################ 
# Requirements:
# - PowerShell 5.1+
# - A Rubrik cluster or EDGE appliance, network access to it and credentials to login
# - Only tested on Rubrik 5.0.0-p2
# - Before running Configure RubrikAdvancedReportingv1-Settings
# - Configure the $ScriptDirectory to a location which contains the below files
# - Run PowerShell as administrator with command "Set-ExecutionPolcity unrestricted" on the host running the script
# - The script will prompt for Rubrik and SMTP creds (if required) on first run and store them in the script directory output as .xml files which can be re-used
################################################
# Legal Disclaimer:
# This script is written by Darren Swift is not supported under any support program or service. 
# All scripts are provided AS IS without warranty of any kind. 
# The author further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
# The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
# In no event shall its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if the author has been advised of the possibility of such damages.
##################################
# Global settings file location
##################################
$ScriptDirectory = "C:\Users\darren.swift.ZERTO\Documents\GitHub\Swifty Rubrik Scripts\WTW_Reports\"
################################################
# Nothing to configure below this line - Starting the main function of the script
################################################
$GlobalSettingsFile = $ScriptDirectory + "RubrikAdvancedReportingv1-Settings.ps1"
$SettingsTest = Test-Path $GlobalSettingsFile 
IF ($SettingsTest -eq $FALSE)
{
"No RubrikAdvancedReportingv1-Settings.ps1 found in directory:" 
$ScriptDirectory
"Verify the ScriptDirectory variable at the start of each script is configured to the correct directory containing the settings and credential files"
sleep 10
# Terminating script as no valid settings file found
kill $pid
}
##################################
# Global settings import of the variables required
##################################
.$GlobalSettingsFile
###############################################
# Importing Rubrik credentials
###############################################
# Setting credential file
$RubrikCredentialsFile = $ScriptDirectory + "RubrikCredentials.xml"
# Testing if file exists
$RubrikCredentialsFileTest =  Test-Path $RubrikCredentialsFile
# IF doesn't exist, prompting and saving credentials
IF ($RubrikCredentialsFileTest -eq $False)
{
$RubrikCredentials = Get-Credential -Message "Enter Rubrik login credentials"
$RubrikCredentials | EXPORT-CLIXML $RubrikCredentialsFile -Force
}
# Importing credentials
$RubrikCredentials = IMPORT-CLIXML $RubrikCredentialsFile
# Setting the username and password from the credential file (run at the start of each script)
$RubrikUser = $RubrikCredentials.UserName
$RubrikPassword = $RubrikCredentials.GetNetworkCredential().Password
###############################################
# Importing SMTP credentials if required
###############################################
# Setting credential file
$SMTPCredentialsFile = $ScriptDirectory + "SMTPCredentials.xml"
# Testing if file exists
$SMTPCredentialsFileTest =  Test-Path $SMTPCredentialsFile
# Prompting for SMTP Credentials if required
IF (($SMTPCredentialsFileTest -eq $False) -and ($SMTPAuthRequired -eq $True) -and ($EnableEmail -eq $True))
{
$SMTPCredentials = Get-Credential -Message "Enter SMTP Authentication credentials"
$SMTPCredentials | EXPORT-CLIXML "C:\RubrikAdvancedReportingv1\SMTPCredentials.xml"
}
# Importing SMTP Credentials if required
IF (($SMTPCredentialsFileTest -eq $True) -and ($SMTPAuthRequired -eq $True) -and ($EnableEmail -eq $True))
{
$SMTPCredentials = IMPORT-CLIXML $SMTPCredentialsFile
}
##################################
# Adding certificate exception to prevent API errors
##################################
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
##########################
# Building Rubrik API string & invoking REST API
##########################
$v1BaseURL = "https://" + $RubrikCluster + "/api/v1/"
$v2BaseURL = "https://" + $RubrikCluster + "/api/v2/"
$InternalURL = "https://" + $RubrikCluster + "/api/internal/"
$RubrikSessionURL = $v1BaseURL + "session"
$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($RubrikUser+":"+$RubrikPassword))}
$Type = "application/json"
# Authenticating with API
Try 
{
$RubrikSessionResponse = Invoke-RestMethod -Uri $RubrikSessionURL -Headers $Header -Method POST -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
# Extracting the token from the JSON response
$RubrikSessionHeader = @{'Authorization' = "Bearer $($RubrikSessionResponse.token)"}
##########################
# Calculating timezone of machine running script
##########################
$SystemDateTime = Get-Date
sleep 1
$UTCDateTime = [System.DateTime]::UtcNow
# Caculating difference
$SystemTimeGapToUTC = New-Timespan –Start $UTCDateTime –End $SystemDateTime
$SystemTimeGapToUTCInHours = $SystemTimeGapToUTC.TotalHours
$SystemTimeGapToUTCInHours = [Math]::Round($SystemTimeGapToUTCInHours, 1)
###############################################
# Getting Cluster Info
###############################################
$ClusterInfoURL = $v1BaseURL+"cluster/me"
Try 
{
$ClusterInfo = Invoke-RestMethod -Uri $ClusterInfoURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$Error[0] | Format-List -Force
}
$ClusterVersion = $ClusterInfo.version
$ClusterName = $ClusterInfo.name
###############################################
# Getting Cluster Status
###############################################
$ClusterStatusURL = $InternalURL+"cluster/me/system_status"
Try 
{
$ClusterStatusData = Invoke-RestMethod -Uri $ClusterStatusURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$Error[0] | Format-List -Force
}
$ClusterStatus = $ClusterStatusData.status
# Fixing capitilzation on status
IF ($ClusterStatus -eq "ok"){$ClusterStatus = "OK"}
###############################################
# Getting Cluster Nodes
###############################################
$ClusterNodesURL = $InternalURL+"cluster/me/node"
Try 
{
$ClusterNodesJSON = Invoke-RestMethod -Uri $ClusterNodesURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
$ClusterNodes = $ClusterNodesJSON.data
}
Catch 
{
$_.Exception.ToString()
$Error[0] | Format-List -Force
}
# Counting nodes
$TotalClusterNodes = $ClusterNodes.Count
$HealthyClusterNodes = $ClusterNodes | Where-Object {$_.status -eq "OK"} | Measure | Select -ExpandProperty Count
$BadClusterNodes = $ClusterNodes | Where-Object {$_.status -ne "OK"} | Measure | Select -ExpandProperty Count
$ClusterNodeSummary = "$HealthyClusterNodes" + "/" + "$TotalClusterNodes"
###############################################
# Getting Cluster Storage Usage
###############################################
$ClusterStorageURL = $InternalURL+"stats/system_storage"
Try 
{
$ClusterStorage = Invoke-RestMethod -Uri $ClusterStorageURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$Error[0] | Format-List -Force
}
$ClusterTotalStorageBytes = $ClusterStorage.total
$ClusterUsedStorageBytes = $ClusterStorage.used
$ClusterFreeStorageBytes = $ClusterStorage.available
$ClusterLiveMountStorageBytes = $ClusterStorage.liveMount
# Converting to GB
$ClusterLiveMountStorageGB = $ClusterLiveMountStorageBytes / 1000 / 1000 / 1000
$ClusterLiveMountStorageGB = [Math]::Round($ClusterLiveMountStorageGB,2)
$ClusterFreeStorageGB = $ClusterFreeStorageBytes / 1000 / 1000 / 1000
$ClusterFreeStorageGB = [Math]::Round($ClusterFreeStorageGB,2)
# Converting to TB
$ClusterTotalStorageTB = $ClusterTotalStorageBytes / 1000 / 1000 / 1000 / 1000
$ClusterTotalStorageTB = [Math]::Round($ClusterTotalStorageTB,2)
$ClusterUsedStorageTB = $ClusterUsedStorageBytes / 1000 / 1000 / 1000 / 1000
$ClusterUsedStorageTB = [Math]::Round($ClusterUsedStorageTB,2)
$ClusterFreeStorageTB = $ClusterFreeStorageBytes / 1000 / 1000 / 1000 / 1000
$ClusterFreeStorageTB = [Math]::Round($ClusterFreeStorageTB,2)
# Calculating percentage used space
$ClusterUsedPercentage = ($ClusterUsedStorageTB/$ClusterTotalStorageTB).tostring("P1")
$ClusterUsedPercentageInt = ($ClusterUsedStorageTB/$ClusterTotalStorageTB)*100
# Enforcing cluster status change if space equal or above 95%
IF ($ClusterUsedPercentageInt -ge 95)
{
$ClusterStatus = "NearMaxCapacity"
}
##################################
# Getting list of SLA Domains
##################################
$SLAListURL = $v2BaseURL+"sla_domain"
Try 
{
$SLAListJSON = Invoke-RestMethod -Uri $SLAListURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
$SLAList = $SLAListJSON.data
}
Catch 
{
$_.Exception.ToString()
$Error[0] | Format-List -Force
}
##################################
# Getting list of VMs
##################################
$VMListURL = $v1BaseURL+"vmware/vm?limit=5000"
Try 
{
$VMListJSON = Invoke-RestMethod -Uri $VMListURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
$VMList = $VMListJSON.data
}
Catch 
{
$_.Exception.ToString()
$Error[0] | Format-List -Force
}
# If $VMList is null, likely that the JSON was too big for the default 2MB MaxJsonLength, fixing with JavaScriptSerializer
IF ($VMList -eq $null)
{
$VMListJSONSerialized = ParseItem ((New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{MaxJsonLength=67108864}).DeserializeObject($VMListJSON))
$VMList = $VMListJSONSerialized.data
}
##################################
# Building list of UnProtected, but Powered On, VMs
##################################
$UnprotectedVMList = $VMList | Where-Object {($_.effectiveSlaDomainName -eq "UNPROTECTED") -and ($_.PowerStatus -eq "poweredOn") -and ($_.isRelic -ne "True")} | Sort-Object name |select name,powerstatus,moid,clusterName,ipAddress,vmwareToolsInstalled
##########################
# Building list of Protected VMs, will use this to create a list of VMs meeting SLA compliance
##################################
$ProtectedVMList = $VMList | Where-Object {($_.effectiveSlaDomainName -ne "UNPROTECTED") -and ($SLADomainsToExclude -notcontains $_.effectiveSlaDomainName) -and ($_.isRelic -ne "True")}
$ProtectedVMListCount = $ProtectedVMList.count
##################################
# Building Report per VM
##################################
$VMProcessingCount = 0
# Creating array to store report info
$VMComplianceReport = @()
$VMComplianceSummary = @()
# Performing per VM action
ForEach ($VM in $ProtectedVMList)
{
# Showing count
$VMProcessingCount ++
"CheckingVM: $VMProcessingCount"+"/"+$ProtectedVMListCount
# Setting variables required
$VMName = $VM.name
$VMIP = $VM.ipAddress
$VMClusterName = $VM.clusterName
$VMPowerStatus = $VM.powerStatus
$VMSLADomain = $VM.effectiveSlaDomainName
$VMSLADomainID = $VM.effectiveSlaDomainId
$VMID = $VM.id
$VMIDShort = $VMID.Substring(17)
# Converting Power Status to shorter names
IF ($VMPowerStatus -eq "PoweredOff"){$VMPowerStatus = "Off"}
IF ($VMPowerStatus -eq "PoweredOn"){$VMPowerStatus = "On"}
##########################
# Getting VM detail
##########################
$VMInfoURL = $v1BaseURL+"vmware/vm/"+$VMID
Try 
{
$VMInfo = Invoke-RestMethod -Uri $VMInfoURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
# Pulling VM detail
$VMSnapshotCount = $VMInfo.snapshotCount
$VMVirtualDisks = $VMInfo.virtualDiskIds.Count
$VMToolInstalled = $VMInfo.vmwareToolsInstalled
$VMGuestOS = $VMInfo.guestOsType
$VMPhysicalStorage = $VMInfo.physicalStorage
##################################
# IF no snapshots exist, not performing any snapshot work as the object is pending a first full backup
##################################
IF ($VMSnapshotCount -eq 0)
{
# No snapshot exists, must be awaiting first full
$SLACompliance = "PendingFirstFull"
# Resetting values to ensure data isn't carried over between rows
$VMLatestSnapshotAdjusted = $null
$SnapshotAdjustedGapInHours = $null
$VMOnDemandRun = $FALSE
$VMSnapshotStorageLogicalMB = $null
$VMSnapshotStorageIngestedMB = $null
$VMSnapshotStoragePhysicalMB = $null
$VMSnapshotStorageLogicalGB = $null
$VMSnapshotStorageIngestedGB = $null
$VMSnapshotStoragePhysicalGB = $null
$VMLastBackupMessage = $null
$VMLastBackupID = $null
$VMBackupTimeTaken = $null
$VMBackupStart = $null
$VMBackupEnd = $null
$VMBackupStartAdjusted = $null
$VMBackupEndAdjusted = $null
}
ELSE
{
# Snapshot exists, so performing actions
##########################
# Getting VM snapshot info
##########################
$VMSnapshotURL = $v1BaseURL+"vmware/vm/"+$VMID+"/snapshot"
Try 
{
$VMSnapshotJSON = Invoke-RestMethod -Uri $VMSnapshotURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
$VMSnapshot = $VMSnapshotJSON.data
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
# Getting VM snapshot consistency level
$VMConsistencyLevel = $VMSnapshot  | Sort-Object -Descending date | select -ExpandProperty consistencyLevel -First 1
# Simplifying app consistency message
IF ($VMConsistencyLevel -eq "VSS_CONSISTENT")
{
$VMAppConsistency = $True
}
ELSE
{
$VMAppConsistency = $False
}
##################################
# Selecting snapshots
##################################
$VMLatestSnapshotID = $VMSnapshot | Sort-Object -Descending date | select -ExpandProperty id -First 1
$VMLatestSnapshot1 = $VMSnapshot | Sort-Object -Descending date | select -ExpandProperty date -First 1
$VMOldestSnapshot1 = $VMSnapshot | Sort-Object date | select -ExpandProperty date -First 1
##################################
# Getting storage stats for latest snapshot ID
##################################
$VMSnapshotStorageURL = $InternalURL+"snapshot/"+$VMLatestSnapshotID+"/storage/stats?snappable_id=VirtualMachine%3A%3A%3A" + $VMIDShort
Try 
{
$VMSnapshotStorage = Invoke-RestMethod -Uri $VMSnapshotStorageURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
$VMSnapshotStorageLogicalBytes = $VMSnapshotStorage.logicalBytes
$VMSnapshotStorageIngestedBytes = $VMSnapshotStorage.ingestedBytes
$VMSnapshotStoragePhysicalBytes = $VMSnapshotStorage.physicalBytes
# Nulling ingested if VM is powered off
IF ($VMPowerStatus -ne "On"){$VMSnapshotStorageIngestedBytes = 0}
# Converting bytes to MB
$VMSnapshotStorageLogicalMB = $VMSnapshotStorageLogicalBytes / 1000 / 1000
$VMSnapshotStorageIngestedMB = $VMSnapshotStorageIngestedBytes / 1000 / 1000
$VMSnapshotStoragePhysicalMB = $VMSnapshotStoragePhysicalBytes / 1000 / 1000
# Rounding up
$VMSnapshotStorageLogicalMB = [Math]::Round($VMSnapshotStorageLogicalMB, 0)
$VMSnapshotStorageIngestedMB = [Math]::Round($VMSnapshotStorageIngestedMB, 0)
$VMSnapshotStoragePhysicalMB = [Math]::Round($VMSnapshotStoragePhysicalMB, 0)
# Converting bytes to GB
$VMSnapshotStorageLogicalGB = $VMSnapshotStorageLogicalBytes / 1000 / 1000 / 1000
$VMSnapshotStorageIngestedGB = $VMSnapshotStorageIngestedBytes / 1000 / 1000 / 1000
$VMSnapshotStoragePhysicalGB = $VMSnapshotStoragePhysicalBytes / 1000 / 1000 / 1000
# Rounding to 2 decimal places
$VMSnapshotStorageLogicalGB = [Math]::Round($VMSnapshotStorageLogicalGB, 1)
$VMSnapshotStorageIngestedGB = [Math]::Round($VMSnapshotStorageIngestedGB, 1)
$VMSnapshotStoragePhysicalGB = [Math]::Round($VMSnapshotStoragePhysicalGB, 1)
##################################
# Converting Latest Snapshot date time to usable format
##################################
# Step 1 - Removing characters and trimming snapshot string for conversion
$VMLatestSnapshot2 = $VMLatestSnapshot1.Replace("T"," ").Replace("Z"," ").TrimEnd()
# Step 2 - Counting characters past 19 (required amount for conversion)
$VMLatestCharCount = $VMLatestSnapshot2 | Measure-Object -Character | Select -ExpandProperty Characters
$VMLatestCharSubtract = $VMLatestCharCount - 19
# Step 3 - Subtracting the diff to ensure conversion works
$VMLatestSnapshot3 = $VMLatestSnapshot2.Substring(0,$VMLatestSnapshot2.Length-$VMLatestCharSubtract)
# Step 4 - Converting string to PowerShell datetime object
$VMLatestSnapshot = ([datetime]::ParseExact($VMLatestSnapshot3,”yyyy-MM-dd HH:mm:ss”,$null))
##########################
# Converting Oldest Snapshot
##########################
# Step 1 - Removing characters and trimming snapshot string for conversion
$VMOldestSnapshot2 = $VMOldestSnapshot1.Replace("T"," ").Replace("Z"," ").TrimEnd()
# Step 2 - Counting characters past 19 (required amount for conversion)
$VMOldestCharCount = $VMOldestSnapshot2 | Measure-Object -Character | Select -ExpandProperty Characters
$VMOldestCharSubtract = $VMOldestCharCount - 19
# Step 3 - Subtracting the diff to ensure conversion works
$VMOldestSnapshot3 = $VMOldestSnapshot2.Substring(0,$VMOldestSnapshot2.Length-$VMOldestCharSubtract)
# Step 4 - Converting string to PowerShell datetime object
$VMOldestSnapshot = ([datetime]::ParseExact($VMOldestSnapshot3,”yyyy-MM-dd HH:mm:ss”,$null))
##########################
# Calculating SLA compliance
##########################
# Calculating time gap from latest snap to current time
$SnapshotGap = New-Timespan –Start $VMLatestSnapshot –End $UTCDateTime
$SnapshotGapInHours = $SnapshotGap.TotalHours
$SnapshotGapInHours = [Math]::Round($SnapshotGapInHours, 1)
# Setting SLA outcome
IF (($SnapshotGapInHours -gt $BusinessSLAInHours) -or ($SnapshotGapInHours -eq $null))
{
$SLACompliance = "NotMeetingSLA"
}
ELSE
{
$SLACompliance = "MeetingSLA"
}
##################################
# Calculating Adjusted snapshots by timezone of machine running script for easier reading in the report
##################################
# Adjusting Latest Snapshot gap
$VMLatestSnapshotAdjusted = $VMLatestSnapshot.AddHours($SystemTimeGapToUTCInHours)
# Adjusting Oldest Snapshot gap
$VMOldestSnapshotAdjusted = $VMOldestSnapshot.AddHours($SystemTimeGapToUTCInHours)
##################################
# Getting last backup status for VM
##################################
$VMEventListURL = $InternalURL + "event?limit=3&event_type=Backup&object_ids=VirtualMachine%3A%3A%3A" + $VMIDShort
Try 
{
$VMEventListJSON = Invoke-RestMethod -Uri $VMEventListURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
$VMEventList = $VMEventListJSON.data
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
$VMEventListFiltered = $VMEventList | Where-Object {(($_.eventStatus -ne "Queued") -or ($_.eventStatus -ne "Info"))} | Select -First 1
# Pulling info
$VMEventSeriesID = $VMEventListFiltered.eventSeriesID
$VMLastBackupStatus = $VMEventListFiltered.eventStatus 
# Getting last VM backup message if backup failed
IF (($VMLastBackupStatus -eq "Failure") -or ($VMLastBackupStatus -eq "Warning"))
{
$VMEventInfo = ConvertFrom-Json $VMEventList.eventInfo
$VMLastBackupMessage = $VMEventInfo.message
$VMLastBackupID = $VMEventInfo.id
}
ELSE
{
$VMEventInfo = $null
$VMLastBackupMessage = $null
$VMLastBackupID = $null
}
# Overriding status to warning if INCONSISTENT and setting custom last backup message
IF (($VMConsistencyLevel -eq "INCONSISTENT") -and ($VMLastBackupStatus -eq "Success"))
{
$VMLastBackupStatus = "Success"
$VMLastBackupMessage = "The VM has been shutdown"
}
# Overriting status to Failed if no VMDKs exist on the VM
IF ($VMVirtualDisks -eq 0)
{
$VMLastBackupStatus = "Failed"
$VMLastBackupMessage = "The VM has no disks"
}
# Overriding status to success if showing info message on successful meeting SLA
IF (($VMLastBackupStatus -eq "Info") -and ($SLACompliance -eq "MeetingSLA"))
{
$VMLastBackupStatus = "Success"
}
##################################
# Getting backup start and end time by event series ID
##################################
$VMEventSeriesURL = $InternalURL + "event_series/" + $VMEventSeriesID
Try 
{
$VMEventSeries = Invoke-RestMethod -Uri $VMEventSeriesURL -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
}
Catch 
{
$_.Exception.ToString()
$error[0] | Format-List -Force
}
# Pulling data
$VMEventSeriesDetail = $VMEventSeries.eventDetailList
$VMBackupStart1 = $VMEventSeries.startTime
$VMBackupEnd1 = $VMEventSeries.endTime
$VMEventStorageIngestedBytes = $VMEventSeries.dataTransferred
# Getting data transferred from event if it exists and overwriting snapshot data, as this is the most accurate measurement
IF ($VMEventStorageIngestedBytes -ne $null)
{
$VMSnapshotStorageIngestedBytes = $VMEventStorageIngestedBytes
# Converting bytes to MB
$VMSnapshotStorageIngestedMB = $VMSnapshotStorageIngestedBytes / 1000 / 1000
# Rounding up
$VMSnapshotStorageIngestedMB = [Math]::Round($VMSnapshotStorageIngestedMB, 0)
# Converting bytes to GB
$VMSnapshotStorageIngestedGB = $VMSnapshotStorageIngestedBytes / 1000 / 1000 / 1000
# Rounding to 2 decimal places
$VMSnapshotStorageIngestedGB = [Math]::Round($VMSnapshotStorageIngestedGB, 1)
}
ELSE
{
# Setting to 0
$VMSnapshotStorageIngestedGB = 0
$VMSnapshotStorageIngestedMB = 0
}
# Due to automatic snapshot consolidation on the backend, even though no data has been ingested it can show as new storage consumed on a snapshot. To prevent user alarm nulling VMSnapshotStoragePhysicalMB/GB
IF ($VMSnapshotStorageIngestedGB -eq 0){$VMSnapshotStoragePhysicalGB = 0; $VMSnapshotStoragePhysicalMB = 0}
##########################
# Converting Start Time
##########################
IF (($VMBackupStart1 -ne $null) -and ($VMBackupEnd1 -ne $null))
{
# Step 1 - Removing characters and trimming snapshot string for conversion
$VMBackupStart2 = $VMBackupStart1.Replace("T"," ").Replace("Z"," ").TrimEnd()
# Step 2 - Counting characters past 19 (required amount for conversion)
$VMBackupStartCharCount = $VMBackupStart2 | Measure-Object -Character | Select -ExpandProperty Characters
$VMBackupStartCharSubtract = $VMBackupStartCharCount - 19
# Step 3 - Subtracting the diff to ensure conversion works
$VMBackupStart3 = $VMBackupStart2.Substring(0,$VMBackupStart2.Length-$VMBackupStartCharSubtract)
# Step 4 - Converting string to PowerShell datetime object
$VMBackupStart = ([datetime]::ParseExact($VMBackupStart3,”yyyy-MM-dd HH:mm:ss”,$null))
##########################
# Converting End Time
##########################
# Step 1 - Removing characters and trimming snapshot string for conversion
$VMBackupEnd2 = $VMBackupEnd1.Replace("T"," ").Replace("Z"," ").TrimEnd()
# Step 2 - Counting characters past 19 (required amount for conversion)
$VMBackupEndCharCount = $VMBackupEnd2 | Measure-Object -Character | Select -ExpandProperty Characters
$VMBackupEndCharSubtract = $VMBackupEndCharCount - 19
# Step 3 - Subtracting the diff to ensure conversion works
$VMBackupEnd3 = $VMBackupEnd2.Substring(0,$VMBackupEnd2.Length-$VMBackupEndCharSubtract)
# Step 4 - Converting string to PowerShell datetime object
$VMBackupEnd = ([datetime]::ParseExact($VMBackupEnd3,”yyyy-MM-dd HH:mm:ss”,$null))
##########################
# Adjusting Start and End Times for current timezone
##########################
$VMBackupStartAdjusted = $VMBackupStart.AddHours($SystemTimeGapToUTCInHours)
$VMBackupEndAdjusted = $VMBackupEnd.AddHours($SystemTimeGapToUTCInHours)
##########################
# Calculating Backup Time Taken
##########################
$VMBackupTime = New-Timespan –Start $VMBackupStart –End $VMBackupEnd
$VMBackupTimeInSeconds = $VMBackupTime | Select -ExpandProperty TotalSeconds
$VMBackupTimeTaken = "{0:g}" -f $VMBackupTime
}
ELSE
{
# Nulling out all the time taken measurements because no backup exists for the VM (or it could be a scheduled backup job, which doesn't impact current compliance
$VMBackupTimeTaken = $null
$VMBackupTimeInSeconds = $null
$VMBackupStart = $null
$VMBackupEnd = $null
$VMBackupStartAdjusted = $null
$VMBackupEndAdjusted = $null
# Nulling ingested/stored storage too, as this was from the last backup not within the SLA
$VMSnapshotStorageIngestedMB = 0
$VMSnapshotStoragePhysicalMB = 0
$VMSnapshotStorageIngestedGB = 0
$VMSnapshotStoragePhysicalGB = 0
}
##################################
# Setting display order priority based on status and SLA
##################################
IF ($SLACompliance -eq "MeetingSLA")
{
$DisplayPriority = 3
}
IF ($VMLastBackupStatus -eq "Warning")
{
$DisplayPriority = 2
}
IF (($SLACompliance -eq "NotMeetingSLA") -or ($VMLastBackupStatus -eq "Failure"))
{
$DisplayPriority = 1
}
##################################
# Automatically running an on-demand snapshot for any backups that are not meeting the SLA compliance if $EnableAutoOnDemandSnapshots equals $TRUE
##################################
IF (($EnableAutoOnDemandSnapshots -eq $TRUE) -AND ($SLACompliance -eq "NotMeetingSLA") -AND ($VMLastBackupStatus -ne "Running"))
{
# Host output
"RemediatingVM: $VMName"
# Building POST URL
$VMOnDemandSnapURL = $v1BaseURL+"vmware/vm/"+$VMID+"/snapshot"
# Building JSON
$VMOnDemandSnapJSON =
"{
""slaId"": ""$VMSLADomainID""
}"
# POST to URL with JSON
Try 
{
$VMOnDemandJob = Invoke-RestMethod -Uri $VMOnDemandSnapURL -Method POST -Body $VMOnDemandSnapJSON -TimeoutSec 100 -Headers $RubrikSessionHeader -ContentType $Type
$VMOnDemandRun = $TRUE
}
Catch 
{
$VMOnDemandRun = $FALSE
$_.Exception.ToString()
$error[0] | Format-List -Force
}
# Waiting 30 seconds before processing next object if on-demand snap was posted to stop overloading in case of multiple objects not meeting
sleep 30
}
ELSE
{
# Didn't run on demand snapshot, setting variable
$VMOnDemandRun = $FALSE
}
# End of ELSE action to IF snapshot count equals 0 below
}
# End of ELSE action to IF snapshot count equals 0 above
##########################
# Summarizing VM info into report
##########################
$VMComplianceReportLine = New-Object PSObject
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "SLADomain" -Value "$VMSLADomain"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "Cluster" -Value "$VMClusterName"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "ClusterTotalStorage" -Value "$ClusterTotalStorageTB"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "TotalClusterNodes" -Value "$TotalClusterNodes"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "ClusterFreeStorage" -Value "$ClusterFreeStorageTB"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "ClusterUsedPercentage" -Value "$ClusterUsedPercentage"  
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "VM" -Value "$VMName"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "DisplayPriority" -Value "$DisplayPriority"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "Status" -Value "$VMLastBackupStatus"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "LastBackup" -Value "$VMLatestSnapshotAdjusted"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "HoursSince" -Value "$SnapshotGapInHours"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "SLAInHours" -Value "$BusinessSLAInHours"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "SLACompliance" -Value "$SLACompliance"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "TimeTaken" -Value "$VMBackupTimeTaken"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "TimeTakenSeconds" -Value $VMBackupTimeInSeconds
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "Start" -Value "$VMBackupStartAdjusted"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "End" -Value "$VMBackupEndAdjusted"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "AppConsistent" -Value "$VMAppConsistency"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "ProtectedGB" -Value $VMSnapshotStorageLogicalGB
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "IngestedGB" -Value $VMSnapshotStorageIngestedGB
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "StoredGB" -Value $VMSnapshotStoragePhysicalGB
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "IngestedMB" -Value $VMSnapshotStorageIngestedMB
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "StoredMB" -Value $VMSnapshotStoragePhysicalMB
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "TotalBackups" -Value $VMSnapshotCount
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "OnDemandRun" -Value "$VMOnDemandRun"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "PowerStatus" -Value "$VMPowerStatus"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "VMTools" -Value "$VMToolInstalled"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "GuestOS" -Value "$VMGuestOS"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "GuestIP" -Value "$VMIP"
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "DiskCount" -Value $VMVirtualDisks
$VMComplianceReportLine | Add-Member -MemberType NoteProperty -Name "Details" -Value "$VMLastBackupMessage"
# Adding row to array
$VMComplianceReport += $VMComplianceReportLine
# End of For Each VM below
}
# End of For Each VM above
#
##########################
# Show VM SLA complaince reports
##########################
"----------------------------------------------"
"SLA Compliance Report"
"----------------------------------------------"
$VMComplianceReport | Sort-Object SLACompliance,SLADomain,Cluster,VM | Format-Table
# $VMComplianceReport | Sort-Object SLACompliance,SLADomain,Cluster,VM | Out-GridView -Title "VM Business SLA Compliance Report"
"----------------------------------------------"
################################################
# Summarizing VMComplianceReport data for email summary table 
################################################
$TotalVMs = $VMComplianceReport | Measure-Object | Select -ExpandProperty Count
$TotalSuccess = $VMComplianceReport | Where-Object {(($_.Status -eq "Success") -or ($_.Status -eq "TaskSuccess"))} | Measure | Select -ExpandProperty Count
$TotalWarning = $VMComplianceReport | Where-Object {$_.Status -eq "Warning"} | Measure | Select -ExpandProperty Count
$TotalComplete = $TotalSuccess + $TotalWarning
$TotalRunning = $VMComplianceReport | Where-Object {(($_.Status -eq "Running") -or ($_.Status -eq "Queued"))} | Measure | Select -ExpandProperty Count
$TotalFailure = $VMComplianceReport | Where-Object {(($_.Status -eq "Failure") -or ($_.Status -eq "Canceled") -or ($_.Status -eq "Canceling"))} | Measure | Select -ExpandProperty Count
$TotalPoweredOn = $VMComplianceReport | Where-Object {$_.PowerStatus -eq "On"} | Measure | Select -ExpandProperty Count
$TotalPoweredOff = $VMComplianceReport | Where-Object {$_.PowerStatus -eq "Off"} | Measure | Select -ExpandProperty Count
$TotalAppConsistent = $VMComplianceReport | Where-Object {$_.AppConsistent -eq $TRUE} | Measure | Select -ExpandProperty Count
$TotalCrashConsistent = $VMComplianceReport | Where-Object {$_.AppConsistent -eq $FALSE} | Measure | Select -ExpandProperty Count
$TotalCancelled = $VMComplianceReport | Where-Object {(($_.Status -eq "Cancelled") -or ($_.Status -eq "Canceling"))} | Measure | Select -ExpandProperty Count
$TotalMeetingSLA = $VMComplianceReport | Where-Object {$_.SLACompliance -eq "MeetingSLA"} | Measure | Select -ExpandProperty Count
$TotalNotMeetingSLA = $VMComplianceReport | Where-Object {$_.SLACompliance -eq "NotMeetingSLA"} | Measure | Select -ExpandProperty Count
$TotalPendingFirstFull = $VMComplianceReport | Where-Object {$_.SLACompliance -eq "PendingFirstFull"} | Measure | Select -ExpandProperty Count
$TotalProtectedGB = $VMComplianceReport | Select -ExpandProperty ProtectedGB | Measure -Sum | Select -ExpandProperty Sum
$TotalIngestedGB = $VMComplianceReport | Select -ExpandProperty IngestedGB | Measure -Sum | Select -ExpandProperty Sum
$TotalStoredGB = $VMComplianceReport | Select -ExpandProperty StoredGB | Measure -Sum | Select -ExpandProperty Sum
$TotalDisks = $VMComplianceReport | Select -ExpandProperty DiskCount | Measure -Sum | Select -ExpandProperty Sum
$TotalNoVMTools = $VMComplianceReport | Where-Object {$_.VMTools -ne "True"} | Select -ExpandProperty VMTools | Measure | Select -ExpandProperty Count
$TotalWindowsVMs = $VMComplianceReport | Where-Object {$_.GuestOS -eq "Windows"} | Select -ExpandProperty VMTools | Measure | Select -ExpandProperty Count
# Removing backups with null dates (waiting for first fulls)
$VMComplianceReportFiltered = $VMComplianceReport | Where-Object {$_.LastBackup -ne ""}
$LatestBackup = $VMComplianceReportFiltered | Sort-Object -Descending LastBackup | select -ExpandProperty LastBackup -First 1
$OldestBackup = $VMComplianceReportFiltered | Sort-Object LastBackup | select -ExpandProperty LastBackup -First 1
$AverageBackupAge = $VMComplianceReportFiltered | select -ExpandProperty HoursSince | Measure -Average | Select -ExpandProperty Average
$AverageBackupAge = [Math]::Round($AverageBackupAge, 2)
$AverageBackupTimeSeconds = $VMComplianceReportFiltered | select -ExpandProperty TimeTakenSeconds | Measure -Average | Select -ExpandProperty Average
# Converting average to required time format
$AverageBackupTimeSeconds = [Math]::Round($AverageBackupTimeSeconds, 0)
$AverageBackupTimeSpan =  [timespan]::fromseconds($AverageBackupTimeSeconds)
$AverageBackupTime = "{0:g}" -f $AverageBackupTimeSpan
# Getting longest backup time
$LongestBackupTimeVM = $VMComplianceReportFiltered | Sort-Object -Descending TimeTakenSeconds | Select -ExpandProperty VM -First 1
$LongestBackupTimeSeconds = $VMComplianceReportFiltered | Sort-Object -Descending TimeTakenSeconds | Select -ExpandProperty TimeTakenSeconds -First 1
$LongestBackupTimeSeconds = [Math]::Round($LongestBackupTimeSeconds, 0)
$LongestBackupTimeSpan =  [timespan]::fromseconds($LongestBackupTimeSeconds)
$LongestBackupTime = "{0:g}" -f $LongestBackupTimeSpan
# Converting totals to percentages
$TotalVMsNotWaitingFirstFull = $TotalVMs - $TotalPendingFirstFull
$BackupSuccessPC = ($TotalVMsNotWaitingFirstFull / $TotalMeetingSLA).ToString("P")
# Making 100% Friendly, otherwise keeping the decimal places
IF ($BackupSuccessPC -eq "100.00%"){$BackupSuccessPC = "100%"}
# Converting to TB and rounding figures
$TotalProtectedTB = $TotalProtectedGB / 1000
$TotalIngestedTB = $TotalIngestedGB / 1000
$TotalStoredTB = $TotalStoredGB / 1000
$TotalProtectedTB = [Math]::Round($TotalProtectedTB, 2)
$TotalIngestedTB = [Math]::Round($TotalIngestedTB, 2)
$TotalStoredTB = [Math]::Round($TotalStoredTB, 2)
# Calculating time between
$BackupGapSpan = New-Timespan –Start $OldestBackup –End $LatestBackup
$BackupGapTime = "{0:c}" -f $BackupGapSpan
################################################
# Summarizing all backups into report
################################################
$VMComplianceSummaryLine = New-Object PSObject
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "TotalVMs" -Value "$TotalVMs"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "SuccessPC" -Value "$BackupSuccessPC"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "Success" -Value "$TotalSuccess"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "Warning" -Value "$TotalWarning"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "Cancelled" -Value "$TotalCancelled"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "Failure" -Value "$TotalFailure"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "Running" -Value "$TotalRunning"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "MeetingSLA" -Value "$TotalMeetingSLA"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "NotMeetingSLA" -Value "$TotalNotMeetingSLA"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "PendingFirstFull" -Value "$TotalPendingFirstFull"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "AppConsistent" -Value "$TotalAppConsistent"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "CrashConsistent" -Value "$TotalCrashConsistent"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "ProtectedTB" -Value "$TotalProtectedTB"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "IngestedTB" -Value "$TotalIngestedTB"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "StoredTB" -Value "$TotalStoredTB"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "LatestBackup" -Value "$LatestBackup"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "OldestBackup" -Value "$OldestBackup"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "Duration" -Value "$BackupGapTime"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "PoweredOn" -Value "$TotalPoweredOn"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "ProtectedDisks" -Value "$TotalDisks"
$VMComplianceSummaryLine | Add-Member -MemberType NoteProperty -Name "VMTools" -Value "$TotalVMTools"
# Adding row to array
$VMComplianceSummary += $VMComplianceSummaryLine
##################################
# Output compliance report to CSV if enabled
##################################
IF ($EnableCSVOutput -eq $TRUE)
{
$CSVFile1 = $CSVOutputDirectory + "\Rubrik-BusinessSLAReport-VMwareVMs-" + $SystemDateTime.ToString("yyyy-MM-dd") + "@" + $SystemDateTime.ToString("HH-mm-ss") + ".csv"
$VMComplianceReport | Sort-Object SLACompliance,Status,SLADomain,Cluster,VM | Export-Csv $CSVFile1 -Force -NoTypeInformation
$CSVFile2 = $CSVOutputDirectory + "\Rubrik-BusinessSLAReport-VMwareVMs-Summary-" + $SystemDateTime.ToString("yyyy-MM-dd") + "@" + $SystemDateTime.ToString("HH-mm-ss") + ".csv"
$VMComplianceSummary | Export-Csv $CSVFile2 -Force -NoTypeInformation
}
################################################
# SMTP Email Settings
################################################
IF ($EnableEmail -eq $TRUE)
{
##################################
# Setting overall outcome of report based on success + meeting SLAs
##################################
# Counting for VMs awaiting backup, to not skew the result
$TotalVMsMinusAwaitingFirstFull = $TotalVMs - $TotalPendingFirstFull
# IF all VM backups success and meeting SLA setting table headers to green
IF (($TotalSuccess -eq $TotalVMsMinusAwaitingFirstFull) -and ($TotalMeetingSLA -eq $TotalVMsMinusAwaitingFirstFull))
{
$SummaryText = "Success"
$TableBackground = $HTMLColorSuccess
}
# If any warnings or cancelled tasks found setting table headers to orange, or if cluster nearing max capacity
IF (($TotalWarning -gt 0) -or ($TotalCancelled -gt 0) -or ($TotalRunning -gt 0) -or ($TotalInconsistent -gt 0) -or ($ClusterStatus -eq "NearMaxCapacity"))
{
$SummaryText = "Warning"
$TableBackground = $HTMLColorWarning
}
# If any failures or VMs not meeting SLA, or the cluster status is bad then irrespective of the above, setting to red
IF (($TotalFailure -gt 0) -or ($TotalNotMeetingSLA -gt 0) -or ($ClusterStatus -eq "bad"))
{
$SummaryText = "Failure"
$TableBackground = $HTMLColorFailure
}
##################################
# SMTP Body - HTML Email style settings
##################################
$TableBackground = "#00B2A9"
$TableBorder = "#00B2A9"
$HTMLTableStyle = @"
<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;border-color:#aaa;}
.tg td{font-family:Arial, sans-serif;font-size:10px;padding:10px 5px;border-style:solid;border-width:0px;overflow:hidden;word-break:normal;border-color:#aaa;color:#333;background-color:#ffffff;border-top-width:1px;border-bottom-width:1px;text-align:left;}
.tg th{font-family:Arial, sans-serif;font-size:10px;font-weight:bold;padding:10px 5px;border-style:solid;border-width:0px;overflow:hidden;word-break:normal;border-color:#aaa;color:#000000;background-color:#aaa;border-top-width:1px;border-bottom-width:1px;text-align:left;}
.tg .tg-tabletop{background-color:#ffffff;vertical-align:top;text-align:left;font-weight:bold}
.tg .tg-tabletopmain{background-color:$TableBackground;color:#ffffff;vertical-align:center;text-align:center;font-weight:bold}
.tg .tg-tablerow{background-color:#ffffff;vertical-align:center;text-align:center}
.tg .tg-emailtop{font-family:Arial, sans-serif;font-size:14px;background-color:$TableBackground;border-color:$TableBackground;vertical-align:top;text-align:left;color:#ffffff}
.tg .tg-emailtopsub{font-family:Arial, sans-serif;font-size:11px;background-color:$TableBackground;border-color:$TableBackground;vertical-align:top;text-align:left;color:#ffffff}
</style>
"@
##################################
# Creating HTML Summary table
##################################
$HTMLBackpStatusTable = @"
<table class="tg" style="width:1000">
  <tr>
    <th class="tg-emailtop">Backup Summary: $SummaryText</th>
  </tr>
  <tr>
    <th class="tg-emailtopsub">Created on $env:COMPUTERNAME at $SystemDateTime using $ClusterName</th>
  </tr>
</table>
<br>
"@
$HTMLSummaryTable = @"
<table class="tg" style="width:1000">
  <tr>
    <th class="tg-tabletop">TotalVMs</th>
    <td class=""tg-tablerow"">$TotalVMs</td>
    <th class="tg-tabletop">MeetingSLA</th>
    <td class=""tg-tablerow"">$TotalMeetingSLA</td>
    <th class="tg-tabletop">AppConsistent</th>
    <td class=""tg-tablerow"">$TotalAppConsistent</td>
    <th class="tg-tabletop">LatestBackup</th>
    <td class=""tg-tablerow"">$LatestBackup</td>
    <th class="tg-tabletop">AverageBackupTime</th>
    <td class=""tg-tablerow"">$AverageBackupTime</td>
    <th class="tg-tabletop">ClusterStatus</th>
    <td class=""tg-tablerow"">$ClusterStatus</td>
  </tr>
 <tr>
    <th class="tg-tabletop">SuccessRate</th>
    <td class=""tg-tablerow"">$BackupSuccessPC</td>
    <th class="tg-tabletop">NotMeetingSLA</th>
    <td class=""tg-tablerow"">$TotalNotMeetingSLA</td>
    <th class="tg-tabletop">CrashConsistent</th>
    <td class=""tg-tablerow"">$TotalCrashConsistent</td>
    <th class="tg-tabletop">OldestBackup</th>
    <td class=""tg-tablerow"">$OldestBackup</td>
    <th class="tg-tabletop">LongestBackupTime</th>
    <td class=""tg-tablerow"">$LongestBackupTime</td>
    <th class="tg-tabletop">Version</th>
    <td class=""tg-tablerow"">$ClusterVersion</td>
 </tr>
 <tr>
    <th class="tg-tabletop">Warning</th>
    <td class=""tg-tablerow"">$TotalWarning</td>
    <th class="tg-tabletop">PendingFirstFull</th>
    <td class=""tg-tablerow"">$TotalPendingFirstFull</td>
    <th class="tg-tabletop">Protected(TB)</th>
    <td class=""tg-tablerow"">$TotalProtectedTB</td>
    <th class="tg-tabletop">TotalDuration</th>
    <td class=""tg-tablerow"">$BackupGapTime</td>
    <th class="tg-tabletop">LongestBackupVM</th>
    <td class=""tg-tablerow"">$LongestBackupTimeVM</td>
    <th class="tg-tabletop">HealthyNodes</th>
    <td class=""tg-tablerow"">$ClusterNodeSummary</td>
 </tr>
 <tr>
    <th class="tg-tabletop">Failure</th>
    <td class=""tg-tablerow"">$TotalFailure</td>
    <th class="tg-tabletop">PoweredOn</th>
	<td class=""tg-tablerow"">$TotalPoweredOn</td>
    <th class="tg-tabletop">Ingested(TB)</th>
    <td class=""tg-tablerow"">$TotalIngestedTB</td>
    <th class="tg-tabletop">ProtectedDisks</th>
    <td class=""tg-tablerow"">$TotalDisks</td>
    <th class="tg-tabletop">WindowsVMs</th>
    <td class=""tg-tablerow"">$TotalWindowsVMs</td>
    <th class="tg-tabletop">TotalStorage(TB)</th>
    <td class=""tg-tablerow"">$ClusterTotalStorageTB</td>
 </tr>
 <tr>
    <th class="tg-tabletop">Running</th>
    <td class=""tg-tablerow"">$TotalRunning</td>
    <th class="tg-tabletop">PoweredOff</th>
    <td class=""tg-tablerow"">$TotalPoweredOff</td>
    <th class="tg-tabletop">Stored(TB)</th>
    <td class=""tg-tablerow"">$TotalStoredTB</td>
    <th class="tg-tabletop">NoVMTools</th>
    <td class=""tg-tablerow"">$TotalNoVMTools</td>
    <th class="tg-tabletop">LinuxVMs</th>
    <td class=""tg-tablerow"">$TotalLinuxVMs</td>
    <th class="tg-tabletop">ClusterStorageFree</th>
    <td class=""tg-tablerow"">$ClusterFreeStorageTB</td>
 </tr>
 </table>
 <br>
"@
##################################
# Creating HTML VM table structure
##################################
$HTMLTableStart = @"
<table class="tg" style="width:100%">
  <tr>
    <th class="tg-tabletopmain">VM</th>
    <th class="tg-tabletopmain">SLADomain</th>
    <th class="tg-tabletopmain">Cluster</th>
	<th class="tg-tabletopmain">Status</th>
    <th class="tg-tabletopmain">LastBackup</th>
    <th class="tg-tabletopmain">HoursSince</th>
    <th class="tg-tabletopmain">SLAInHours</th>
    <th class="tg-tabletopmain">Compliance</th>
    <th class="tg-tabletopmain">Start</th>
    <th class="tg-tabletopmain">End</th>
    <th class="tg-tabletopmain">TimeTaken</th>
	<th class="tg-tabletopmain">VSS</th>
	<th class="tg-tabletopmain">ProtectedGB</th>
	<th class="tg-tabletopmain">IngestedGB</th>
	<th class="tg-tabletopmain">StoredGB</th>
    <th class="tg-tabletopmain">TotalBackups</th>
    <th class="tg-tabletopmain">Remediated</th>
    <th class="tg-tabletopmain">Power</th>
    <th class="tg-tabletopmain">VMTools</th>
    <th class="tg-tabletopmain">GuestOS</th>
    <th class="tg-tabletopmain">VMDKs</th>
	<th class="tg-tabletopmain">Details</th>
  </tr>
"@
$HTMLTableEnd = @"
</table>
<br>
"@
##################################
# Creating the Report Email Body
##################################
# Building email list by task to put the most important objects for viewing at the top
$ReportList = $VMComplianceReport | Sort-Object DisplayPriority,Status,SLACompliance,VM
# Nulling out table, protects against issues with multiple runs in PowerShell ISE
$HTMLReportTableMiddle = $null
# Creating table row for each line
ForEach ($Row in $ReportList) 
{
# Setting values
$HTML1VM = $Row.VM
$HTML1SLADomain = $Row.SLADomain
$HTML1Cluster = $Row.Cluster
$HTML1Status = $Row.Status
$HTML1LastBackup = $Row.LastBackup
$HTML1HoursSince = $Row.HoursSince
$HTML1SLAInHours = $Row.SLAInHours
$HTML1SLACompliance = $Row.SLACompliance
$HTML1StartTime = $Row.Start
$HTML1TimeTaken = $Row.TimeTaken
$HTML1EndTime = $Row.End
$HTML1Consistency = $Row.AppConsistent
$HTML1ProtectedGB = $Row.ProtectedGB
$HTML1IngestedGB = $Row.IngestedGB
$HTML1StoredGB = $Row.StoredGB
$HTML1TotalBackups = $Row.TotalBackups
$HTML1OnDemandRun = $Row.OnDemandRun
$HTML1PowerStatus = $Row.PowerStatus
$HTML1VMTools = $Row.VMTools
$HTML1GuestOS = $Row.GuestOS
$HTML1GuestIP = $Row.GuestIP
$HTML1DiskCount = $Row.DiskCount
$HTML1Details = $Row.Details
# Setting colors for Status
IF (($HTML1Status -eq "Failure") -or ($HTML1Status -eq "Canceled") -or ($HTML1Status -eq "Canceling")) {$HTMLStatusColor =  $HTMLColorFailure}
IF (($HTML1Status -eq "Success") -or ($HTML1Status -eq "TaskSuccess")) {$HTMLStatusColor =  $HTMLColorSuccess}
IF (($HTML1Status -eq "Warning") -or ($HTML1Status -eq "Running") -or ($HTML1Consistency -eq "INCONSISTENT")) {$HTMLStatusColor =  $HTMLColorWarning}
# Setting colors for SLA
IF ($HTML1SLACompliance -eq "MeetingSLA") {$HTMLComplianceColor =  $HTMLColorSuccess}
IF ($HTML1SLACompliance -eq "NotMeetingSLA") {$HTMLComplianceColor =  $HTMLColorFailure}
# Building HTML table row
$HTMLReportTableRow = "
<tr>
    <td class=""tg-tablerow"">$HTML1VM</td>
    <td class=""tg-tablerow"">$HTML1SLADomain</td>
    <td class=""tg-tablerow"">$HTML1Cluster</td>
	<td class=""tg-tablerow""><font color=$HTMLStatusColor>$HTML1Status</font></td>
    <td class=""tg-tablerow"">$HTML1LastBackup</td>
    <td class=""tg-tablerow"">$HTML1HoursSince</td>
    <td class=""tg-tablerow"">$HTML1SLAInHours</td>
    <td class=""tg-tablerow""><font color=$HTMLComplianceColor>$HTML1SLACompliance</font></td>
    <td class=""tg-tablerow"">$HTML1StartTime</td>
    <td class=""tg-tablerow"">$HTML1EndTime</td>
    <td class=""tg-tablerow"">$HTML1TimeTaken</td>
	<td class=""tg-tablerow"">$HTML1Consistency</td>
	<td class=""tg-tablerow"">$HTML1ProtectedGB</td>
	<td class=""tg-tablerow"">$HTML1IngestedGB</td>
	<td class=""tg-tablerow"">$HTML1StoredGB</td>
    <td class=""tg-tablerow"">$HTML1TotalBackups</td>
    <td class=""tg-tablerow"">$HTML1OnDemandRun</td>
    <td class=""tg-tablerow"">$HTML1PowerStatus</td>
    <td class=""tg-tablerow"">$HTML1VMTools</td>
    <td class=""tg-tablerow"">$HTML1GuestOS</td>
    <td class=""tg-tablerow"">$HTML1DiskCount</td>
	<td class=""tg-tablerow"">$HTML1Details</td>
  </tr>
"
# Adding row to table
$HTMLReportTableMiddle += $HTMLReportTableRow
}
##################################
# Creating the Failure Email Body
##################################
$FailureList = $VMComplianceReport | Where-Object {(($_.SLACompliance -eq "NotMeetingSLA"))} | Sort-Object SLACompliance,SLADomain,Cluster,VM
# Nulling out table, protects against issues with multiple runs in PowerShell ISE
$HTMLFailureReportTableMiddle = $null
# Creating table row for each line
ForEach ($Row in $FailureList) 
{
# Setting values
$HTML2VM = $Row.VM
$HTML2SLADomain = $Row.SLADomain
$HTML2Cluster = $Row.Cluster
$HTML2Status = $Row.Status
$HTML2LastBackup = $Row.LastBackup
$HTML2HoursSince = $Row.HoursSince
$HTML2SLAInHours = $Row.SLAInHours
$HTML2SLACompliance = $Row.SLACompliance
$HTML2StartTime = $Row.Start
$HTML2TimeTaken = $Row.TimeTaken
$HTML2EndTime = $Row.End
$HTML2Consistency = $Row.AppConsistent
$HTML2ProtectedGB = $Row.ProtectedGB
$HTML2IngestedGB = $Row.IngestedGB
$HTML2StoredGB = $Row.StoredGB
$HTML2TotalBackups = $Row.TotalBackups
$HTML2OnDemandRun = $Row.OnDemandRun
$HTML2PowerStatus = $Row.PowerStatus
$HTML2VMTools = $Row.VMTools
$HTML2GuestOS = $Row.GuestOS
$HTML2GuestIP = $Row.GuestIP
$HTML2DiskCount = $Row.DiskCount
$HTML2Details = $Row.Details
# Setting colors for Status
IF (($HTML2Status -eq "Failure") -or ($HTML2Status -eq "Canceled") -or ($HTML2Status -eq "Canceling")) {$HTMLStatusColor =  $HTMLColorFailure}
IF (($HTML2Status -eq "Success") -or ($HTML2Status -eq "TaskSuccess")) {$HTMLStatusColor =  $HTMLColorSuccess}
IF (($HTML2Status -eq "Warning") -or ($HTML2Status -eq "Running") -or ($HTML2Consistency -eq "INCONSISTENT")) {$HTMLStatusColor =  $HTMLColorWarning}
# Setting colors for SLA
IF ($HTML2SLACompliance -eq "MeetingSLA") {$HTMLComplianceColor =  $HTMLColorSuccess}
IF ($HTML2SLACompliance -eq "NotMeetingSLA") {$HTMLComplianceColor =  $HTMLColorFailure}
# Building HTML table row
$HTMLFailureReportTableRow = "
<tr>
    <td class=""tg-tablerow"">$HTML2VM</td>
    <td class=""tg-tablerow"">$HTML2SLADomain</td>
    <td class=""tg-tablerow"">$HTML2Cluster</td>
	<td class=""tg-tablerow""><font color=$HTMLStatusColor>$HTML2Status</font></td>
    <td class=""tg-tablerow"">$HTML2LastBackup</td>
    <td class=""tg-tablerow"">$HTML2HoursSince</td>
    <td class=""tg-tablerow"">$HTML2SLAInHours</td>
    <td class=""tg-tablerow""><font color=$HTMLComplianceColor>$HTML2SLACompliance</font></td>
    <td class=""tg-tablerow"">$HTML2StartTime</td>
    <td class=""tg-tablerow"">$HTML2EndTime</td>
    <td class=""tg-tablerow"">$HTML2TimeTaken</td>
	<td class=""tg-tablerow"">$HTML2Consistency</td>
	<td class=""tg-tablerow"">$HTML2ProtectedGB</td>
	<td class=""tg-tablerow"">$HTML2IngestedGB</td>
	<td class=""tg-tablerow"">$HTML2StoredGB</td>
    <td class=""tg-tablerow"">$HTML2TotalBackups</td>
    <td class=""tg-tablerow"">$HTML2OnDemandRun</td>
    <td class=""tg-tablerow"">$HTML2PowerStatus</td>
    <td class=""tg-tablerow"">$HTML2VMTools</td>
    <td class=""tg-tablerow"">$HTML2GuestOS</td>
    <td class=""tg-tablerow"">$HTML2DiskCount</td>
	<td class=""tg-tablerow"">$HTML2Details</td>
  </tr>
"
# Adding row to table
$HTMLFailureReportTableMiddle += $HTMLFailureReportTableRow
}
##################################
# Creating Emails
##################################
# Report email
$HTMLReport = $HTMLTableStyle + $HTMLBackpStatusTable + $HTMLSummaryTable + $HTMLTableStart + $HTMLReportTableMiddle + $HTMLTableEnd
# Failure email
$HTMLFailureReport = $HTMLTableStyle + $HTMLBackpStatusTable + $HTMLSummaryTable + $HTMLTableStart + $HTMLFailureReportTableMiddle + $HTMLTableEnd
##################################
# SMTPAuthRequired $TRUE section - Importing credentials if required
##################################
IF ($SMTPAuthRequired -eq $TRUE)
{
##################################
# Sending Report email
##################################
IF ($SMTPSSLEnabled -eq $True)
{
# Using SSL if $SMTPSSLEnabled equals TRUE
Send-MailMessage -To $ReportEmailTo -From $EmailFrom -Subject $ReportEmailSubject -BodyAsHtml -Body $HTMLReport -SmtpServer $SMTPServer -Port $SMTPPort -Credential $SMTPCredentials -UseSsl
}
ELSE
{
Send-MailMessage -To $ReportEmailTo -From $EmailFrom -Subject $ReportEmailSubject -BodyAsHtml -Body $HTMLReport -SmtpServer $SMTPServer -Port $SMTPPort -Credential $SMTPCredentials
}
##################################
# Sending Auto IT Ticket email, but only if objects found to be NotMeetingSLA
##################################
IF ($FailureList -ne $null)
{
IF ($SMTPSSLEnabled -eq $True)
{
# Using SSL if $SMTPSSLEnabled equals TRUE
Send-MailMessage -To $FailureEmailTo -From $EmailFrom -Subject $FailureEmailSubject -BodyAsHtml -Body $HTMLFailureReport -SmtpServer $SMTPServer -Port $SMTPPort -Credential $SMTPCredentials -UseSsl
}
ELSE
{
Send-MailMessage -To $FailureEmailTo -From $EmailFrom -Subject $FailureEmailSubject -BodyAsHtml -Body $HTMLFailureReport -SmtpServer $SMTPServer -Port $SMTPPort -Credential $SMTPCredentials
}
# End of auto IT ticket email below
}
# End of auth required below
}
##################################
# End of auth required above, sending the same emails without authentication if specified in the settings
##################################
ELSE
{
##################################
# Sending Report email
##################################
Send-MailMessage -To $ReportEmailTo -From $EmailFrom -Subject $ReportEmailSubject -BodyAsHtml -Body $HTMLReport -SmtpServer $SMTPServer -Port $SMTPPort -Credential $SMTPCredentials -UseSsl
##################################
# Sending Auto IT Ticket email, but only if objects found to be NotMeetingSLA
##################################
IF ($FailureList -ne $null)
{
Send-MailMessage -To $FailureEmailTo -From $EmailFrom -Subject $FailureEmailSubject -BodyAsHtml -Body $HTMLFailureReport -SmtpServer $SMTPServer -Port $SMTPPort
}
}
# End of email section below
}
# End of email section above
###############################################
# End of script
###############################################