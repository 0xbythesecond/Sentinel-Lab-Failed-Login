# Sentinel Lab Failed Login

## Introduction
This lab will help you get ramped up with Microsoft Sentinel and provide hands-on practical experience for product features, capabilities, and scenarios. 

We will set up Azure Sentinel (SIEM) and connect it to a live virtual machine acting as a honey pot. We will observe live attacks (RDP Brute Force) from all around the world. We will use a custom PowerShell script to look up the attackers Geolocation information and plot it on the Azure Sentinel Map and the fact that Microsoft Sentinel offers a 30-day free trial.

## Prerequisites

To deploy Microsoft Sentinel Trainig Lab, **you must have a Microsoft Azure subscription**. If you do not have an existing Azure subscription, you can sign up for a free trial [here](https://azure.microsoft.com/free/).
The Powershell script in this repository is responsible for parsing out Windows Event Log information for failed RDP attacks and using a third party API to collect geographic information about the attackers location.

<details>
 <summary><h3> 📜 PowerShell Script </h3></summary>   
# Get API key from here: https://ipgeolocation.io/
$API_KEY      = "d4600b4efdef42b39828f5155041a457"
$LOGFILE_NAME = "failed_rdp.log"
$LOGFILE_PATH = "C:\ProgramData\$($LOGFILE_NAME)"

# This filter will be used to filter failed RDP events from Windows Event Viewer
$XMLFilter = @'
<QueryList> 
   <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
</QueryList> 
'@

<#
    This function creates a bunch of sample log files that will be used to train the
    Extract feature in Log Analytics workspace. If you don't have enough log files to
    "train" it, it will fail to extract certain fields for some reason -_-.
    We can avoid including these fake records on our map by filtering out all logs with
    a destination host of "samplehost"
#>
Function write-Sample-Log() {
    "latitude:47.91542,longitude:-120.60306,destinationhost:samplehost,username:fakeuser,sourcehost:24.16.97.222,state:Washington,country:United States,label:United States - 24.16.97.222,timestamp:2021-10-26 03:28:29" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-22.90906,longitude:-47.06455,destinationhost:samplehost,username:lnwbaq,sourcehost:20.195.228.49,state:Sao Paulo,country:Brazil,label:Brazil - 20.195.228.49,timestamp:2021-10-26 05:46:20" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37022,longitude:4.89517,destinationhost:samplehost,username:CSNYDER,sourcehost:89.248.165.74,state:North Holland,country:Netherlands,label:Netherlands - 89.248.165.74,timestamp:2021-10-26 06:12:56" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:40.71455,longitude:-74.00714,destinationhost:samplehost,username:ADMINISTRATOR,sourcehost:72.45.247.218,state:New York,country:United States,label:United States - 72.45.247.218,timestamp:2021-10-26 10:44:07" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:33.99762,longitude:-6.84737,destinationhost:samplehost,username:AZUREUSER,sourcehost:102.50.242.216,state:Rabat-Salé-Kénitra,country:Morocco,label:Morocco - 102.50.242.216,timestamp:2021-10-26 11:03:13" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-5.32558,longitude:100.28595,destinationhost:samplehost,username:Test,sourcehost:42.1.62.34,state:Penang,country:Malaysia,label:Malaysia - 42.1.62.34,timestamp:2021-10-26 11:04:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:41.05722,longitude:28.84926,destinationhost:samplehost,username:AZUREUSER,sourcehost:176.235.196.111,state:Istanbul,country:Turkey,label:Turkey - 176.235.196.111,timestamp:2021-10-26 11:50:47" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:55.87925,longitude:37.54691,destinationhost:samplehost,username:Test,sourcehost:87.251.67.98,state:null,country:Russia,label:Russia - 87.251.67.98,timestamp:2021-10-26 12:13:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37018,longitude:4.87324,destinationhost:samplehost,username:AZUREUSER,sourcehost:20.86.161.127,state:North Holland,country:Netherlands,label:Netherlands - 20.86.161.127,timestamp:2021-10-26 12:33:46" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:17.49163,longitude:-88.18704,destinationhost:samplehost,username:Test,sourcehost:45.227.254.8,state:null,country:Belize,label:Belize - 45.227.254.8,timestamp:2021-10-26 13:13:25" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-55.88802,longitude:37.65136,destinationhost:samplehost,username:Test,sourcehost:94.232.47.130,state:Central Federal District,country:Russia,label:Russia - 94.232.47.130,timestamp:2021-10-26 14:25:33" | Out-File $LOGFILE_PATH -Append -Encoding utf8
}

# This block of code will create the log file if it doesn't already exist
if ((Test-Path $LOGFILE_PATH) -eq $false) {
    New-Item -ItemType File -Path $LOGFILE_PATH
    write-Sample-Log
}

# Infinite Loop that keeps checking the Event Viewer logs.
while ($true)
{
    
    Start-Sleep -Seconds 1
    # This retrieves events from Windows EVent Viewer based on the filter
    $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction SilentlyContinue
    if ($Error) {
        #Write-Host "No Failed Logons found. Re-run script when a login has failed."
    }

    # Step through each event collected, get geolocation
    #    for the IP Address, and add new events to the custom log
    foreach ($event in $events) {


        # $event.properties[19] is the source IP address of the failed logon
        # This if-statement will proceed if the IP address exists (>= 5 is arbitrary, just saying if it's not empty)
        if ($event.properties[19].Value.Length -ge 5) {

            # Pick out fields from the event. These will be inserted into our new custom log
            $timestamp = $event.TimeCreated
            $year = $event.TimeCreated.Year

            $month = $event.TimeCreated.Month
            if ("$($event.TimeCreated.Month)".Length -eq 1) {
                $month = "0$($event.TimeCreated.Month)"
            }

            $day = $event.TimeCreated.Day
            if ("$($event.TimeCreated.Day)".Length -eq 1) {
                $day = "0$($event.TimeCreated.Day)"
            }
            
            $hour = $event.TimeCreated.Hour
            if ("$($event.TimeCreated.Hour)".Length -eq 1) {
                $hour = "0$($event.TimeCreated.Hour)"
            }

            $minute = $event.TimeCreated.Minute
            if ("$($event.TimeCreated.Minute)".Length -eq 1) {
                $minute = "0$($event.TimeCreated.Minute)"
            }


            $second = $event.TimeCreated.Second
            if ("$($event.TimeCreated.Second)".Length -eq 1) {
                $second = "0$($event.TimeCreated.Second)"
            }

            $timestamp = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"
            $eventId = $event.Id
            $destinationHost = $event.MachineName# Workstation Name (Destination)
            $username = $event.properties[5].Value # Account Name (Attempted Logon)
            $sourceHost = $event.properties[11].Value # Workstation Name (Source)
            $sourceIp = $event.properties[19].Value # IP Address
        

            # Get the current contents of the Log file!
            $log_contents = Get-Content -Path $LOGFILE_PATH

            # Do not write to the log file if the log already exists.
            if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
            
                # Announce the gathering of geolocation data and pause for a second as to not rate-limit the API
                #Write-Host "Getting Latitude and Longitude from IP Address and writing to log" -ForegroundColor Yellow -BackgroundColor Black
                Start-Sleep -Seconds 1

                # Make web request to the geolocation API
                # For more info: https://ipgeolocation.io/documentation/ip-geolocation-api.html
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
                $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT

                # Pull Data from the API response, and store them in variables
                $responseData = $response.Content | ConvertFrom-Json
                $latitude = $responseData.latitude
                $longitude = $responseData.longitude
                $state_prov = $responseData.state_prov
                if ($state_prov -eq "") { $state_prov = "null" }
                $country = $responseData.country_name
                if ($country -eq "") {$country -eq "null"}

                # Write all gathered data to the custom log file. It will look something like this:
                #
                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov), country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
            }
            else {
                # Entry already exists in custom log file. Do nothing, optionally, remove the # from the line below for output
                # Write-Host "Event already exists in the custom log. Skipping." -ForegroundColor Gray -BackgroundColor Black
            }
        }
    }
}
</details>
 
## Description
<ul> <li>Configure and Deploy Azure Resources such as Log Analytics Workspace, Virtual Machines, and Azure Sentinel.</li>
 </ul>
 
 
 ## Step 1
 
 
We will create a Virtua Machine that will be exposed to the internet where people around world will be able to attack it. Bad actors will try to login to this Virtual Machine once they've discovered that it's now online. While creating the Virtual Machine, we will create a new Resource Group as well.
 
We search Virtual Machine at top of the page, and once the page loads will choose the '+ Create' button to begin the first steps of creating the virtual machine.
<p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Create Virtual Machine"/></p>
 
Here we will be using East US for the region 
<p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Enter details for Virtual Machine"/></p>
 
In the Networking portion, we will select to change the NIC Network Security Group (NSG) from Basic to Advanced to adjust the inbound rules of the NSG to allow everything into the Virtual Machine.
 
<p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Create New NSG"/></p>
 
Adjusting the inbound rules will appear as follows:
 <pre>
 <b>Source </b>
 any
 <b>Source port ranges </b> 
 * 
 <b>Destination </b>
 any 
 <b>Service </b>
 custom
 <b>Destination port ranges </b>
 *
 <b>Protocol</b>
 any
 <b>Priority</b>
 100</pre>
 <p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Change inboud rules details"/></p>
 Once these have been looked over, we can now select to 'Review + Create"
 <p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Review Create Virtual Machine"/></p>
 
Validation of Creation of VM
 
Now, we are going to create our Log Analytics Workspace to receive or ingest logs from the virtual machine such as windows event logs and our custom logs that has geographic information in order to discover where the attackers are located. Our SIEM will be able to connect to the workspace to be able to display the geo-data on the map that will be created later in the lab. 
 
<p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Create Log Analytics Workspace"/></p>
 
<p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Enter Details for Log Analytics Workspace"/></p>
 
Next, you will 'Review + Create' the log analytics workspace
<p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Review + Create LAW"/></p>
 
We can now search for 'Security Center' at the top of the page so that we can enable the ability to gather logs from the Virtual Machine.  
<p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Security Center"/></p>
 
To do so, we will navigate to 'Pricing & Settings' then select the log analytics workspace that we create previously that is displayed a selectable option. We will then, select to turn 'Azure Defender On' and then turn <b>OFF</b> 'SQL Servers on Machine'. Once this is done, you will select to '<b> Save </b>'. 
<p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Pricing & Settings"/></p>
 
Following this, we will select 'Data Collection' in the left pane and enable 'All Events' option under store additional raw data - windows securtity events then choose to '<b> Save</b>'.
<p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Select All Events"/></p>
 
We can now go back to our log analytics worspace to connect our Virtual Machine. Search 'Log Analytics Workspace' and then scroll down to select the Virtual Machine option. You will choose the VM that we created previously then select the chainlink to 'Connect' the VM to the log analytics workspace. 
 <p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Select Virtual Machine in List"/></p>
 
<p align="center"><img src="https://i.imgur.com/DJmEXEB.png" height="50%" width="50%" alt="Connect Virtual Machine"/></p>



 
 







 
