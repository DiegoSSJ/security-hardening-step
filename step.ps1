<# 
Author(s): Bruce Lee, Grant Killian, Kelly Rusk, Jimmy Rudley
Colaborator: Diego Saavedra San Juan
Created Date: August 4, 2016
Modified Date: August 5, 2016
This is the Rackspace Managed Services for Sitecore (https://www.rackspace.com/digital/sitecore) script for security hardening a Sitecore environment 
If the Execution Policy does not allow execution, you may need to run the following interactively to allow a scoped session bypass. 
This is secure as it requires interaction on server and cannot be executed from a script:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
1. Deny anonymous users access to key folders
2. Disable client RSS feeds
3. Secure the file upload functionality
4. Improve the security of the website folder
5. Increase login security
6. Limit access to certain file types
7. Protect PhantomJS
8. Protect media requests
9. Remove header information from responses sent by your website
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$siteName,      # The name of the site as seen in IIS
    [Parameter(Mandatory=$true)]
    [string]$mediaRequestSharedSecretGuid,    # The GUID to protect the media requests with, using Shared Secret
    [Parameter(Mandatory=$false)]
    [string]$extraInclude,  # The subpath to the folder where the extra included files will be 
    [Parameter(Mandatory=$false)]
    [string]$role="cm",  # The role the instance has. One of CM or CD
    [Parameter(Mandatory=$false)]
    [string]$dataFolderPath,     # The path to the Sitecore data folder.     
    [Parameter(Mandatory=$false)]
    [string]$stepsString="123456789")     # Optional string specifying steps to apply. 

        
$site = get-website -name $siteName
$sitecoreRoot = $site.physicalPath   
$sitecoreAppIncludeDirectory = "{0}\app_config\include" -f $sitecoreRoot 
if ( $extraInclude -eq $null -or $extraInclude -eq "" )
    { $extraInclude = $sitecoreAppIncludeDirectory+"\zz" }

# read in Web.config
$webConfigPath = "{0}\web.config" -f $site.physicalPath

Write-Host 'Steps string is '$stepsString 

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 1 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Deny anonymous users access to key folders 
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if ( $stepsString.Contains("1") )
{
    $filterString = "/system.Webserver/security/authentication/anonymousauthentication"
    $app_ConfigLocation = "{0}/App_Config" -f $siteName
    $adminLocation = "{0}/sitecore/admin" -f $siteName
    $debugLocation = "{0}/sitecore/debug" -f $siteName
    $ShellWebserviceLocation = "{0}/sitecore/shell/webservice" -f $siteName
    Set-WebConfigurationProperty -filter $filterString -name enabled -value false -Location $app_ConfigLocation
    Set-WebConfigurationProperty -filter $filterString -name enabled -value false -Location $adminLocation
    Set-WebConfigurationProperty -filter $filterString -name enabled -value false -Location $debugLocation
    Set-WebConfigurationProperty -filter $filterString -name enabled -value false -Location $ShellWebserviceLocation

    Write-Output "Step 1 completed - Deny anonymous users access to key folders"
}
else 
{
    Write-Output "Step 1 skipped - Not in stepsStrings variable"
}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 2 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Disable client RSS feeds
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if ( $stepsString.Contains("2") )
{
	[xml] $webConfigXML = Get-Content $webConfigPath
	#remove the following handler in the <httpHanderls> section in the web.config
	$targetName = "Sitecore.FeedRequestHandler"
	$nodePath = "configuration/system.webServer/handlers/add[@name='{0}']" -f $targetName
	$node = $webConfigXML.SelectSingleNode($nodePath)
	if($node -ne $null)
	{
		$webConfigXML.configuration.'system.webServer'.handlers.RemoveChild($node)
	}
	$webConfigXML.Save($webConfigPath)

	Write-Output "Step 2 completed - Disable client RSS feeds"

}
else 
{
    Write-Output "Step 2 skipped - Not in stepsStrings variable"
}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 3 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Secure the file upload functionality
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if ( $stepsString.Contains("3") )
{

	#Deny Script and Execute permission on /upload folder
	$psPath = "MACHINE/WEBROOT/APPHOST/{0}/upload" -f $site.name
	$filter = "system.webServer/handlers/@AccessPolicy"
	Set-WebConfiguration -Filter $filter -Value "Read" -PSPath $psPath

	#Deny Script and Execute permission on /temp folder
	$psPath = "MACHINE/WEBROOT/APPHOST/{0}/temp" -f $site.name
	$filter = "system.webServer/handlers/@AccessPolicy"
	Set-WebConfiguration -Filter $filter -Value "Read" -PSPath $psPath

	#Remove the SitecoreUploadWatcher         
	$xml = [xml](get-content $webConfigPath) 
	foreach( $item in  $xml.configuration."system.webServer".modules.add )             
	{
			if( $item.name -eq "SitecoreUploadWatcher" )                                                 
			{
				  $xml.configuration."system.webServer".modules.RemoveChild($item);   
			}
	}

	$xml.Save($webConfigPath) 

    $WebsiteBin = "{0}\bin" -f $sitecoreRoot 
	Copy-Item -Path .\UploadFilter.config -Destination $extraInclude
	Copy-Item -Path .\Sitecore.UploadFilter.dll -Destination $WebsiteBin
	 
	Write-Output "Step 3 completed - Secure the file upload functionality"

}
else 
{
    Write-Output "Step 3 skipped - Not in stepsStrings variable"
}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 4 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Improve the security of the website folder
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if ( $stepsString.Contains("4") )
{

	#This is mostly handled during our scripted install; this is a snippet from those procedures
	<# $sitecoreDataDirectory = "D:/outside/of/webroot"
	$sitecoreAppIncludeDirectory = "{0}\app_config\include" -f $sitecoreRoot 
	$rackspaceInclude = $sitecoreAppIncludeDirectory + "\Z.Rackspace"

	if( !(test-path $rackspaceInclude) )
	{
		mkdir $rackspaceInclude
	}


	$dataFolderConfigPath = "{0}\DataFolder.config.example" -f $sitecoreAppIncludeDirectory
	[xml]$dataConfigXML = Get-Content $dataFolderConfigPath
	$dataConfigXML.configuration.sitecore.'sc.variable'.attribute.'#text' = $sitecoreDataDirectory
	$dataConfigXML.Save($dataFolderConfigPath)
	$newFilename = (Get-ChildItem $dataFolderConfigPath).BaseName
	Rename-Item -Path $dataFolderConfigPath -NewName $newFilename #>

	Write-Output "Step 4 completed - Improve the security of the website folder. Handled on Octopus Step 'Set up Data Folder'"

}
else 
{
    Write-Output "Step 4 skipped - Not in stepsStrings variable"
}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 5 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Increase login security
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


if ( $stepsString.Contains("5") )
{
	Copy-Item -Path .\IncreaseLoginSecurity.config -Destination $extraInclude

	Write-Output "Step 5 completed - Increase login security"
}
else 
{
    Write-Output "Step 5 skipped - Not in stepsStrings variable"
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 6 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Limit access to certain file types
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


if ( $stepsString.Contains("6") )
{
	$psPath = "MACHINE/WEBROOT/APPHOST/{0}" -f $site.name
	$filter = "system.webServer/handlers/"
	if ( (Get-WebHandler -Name "xml (integrated)" -PSPath $psPath).name -eq $null )
		{ New-WebHandler -Path *.xml -Verb * -Type "System.Web.HttpForbiddenHandler" -Name "xml (integrated)" -Precondition integratedMode -PSPath $psPath }
	if ( (Get-WebHandler -Name "xslt (integrate)" -PSPath $psPath).name -eq $null )
		{ New-WebHandler -Path *.xslt -Verb * -Type "System.Web.HttpForbiddenHandler" -Name "xslt (integrate)" -Precondition integratedMode -PSPath $psPath }
	if ( (Get-WebHandler -Name "config.xml (integrate)" -PSPath $psPath).name -eq $null )
		{ New-WebHandler -Path *.config.xml -Verb * -Type "System.Web.HttpForbiddenHandler" -Name "config.xml (integrate)" -Precondition integratedMode -PSPath $psPath }
	if ( (Get-WebHandler -Name "mrt (integrate)" -PSPath $psPath).name -eq $null )
		{ New-WebHandler -Path *.mrt -Verb * -Type "System.Web.HttpForbiddenHandler" -Name "mrt (integrate)" -Precondition integratedMode -PSPath $psPath }
		
	Write-Output "Step 6 completed - Limit access to certain file types"

}
else 
{
    Write-Output "Step 6 skipped - Not in stepsStrings variable"
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 7 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Protect PhantomJS --generally not suitable for Content Management (CM) servers
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


if ( $stepsString.Contains("7") )
{
	if ( $role.ToUpper() -ne "CM" )
	{
		$dataFolderValue = "";
		if ( $dataFolderPath -eq $null  -or $dataFolderPath -eq "" )
		{
			$dataFolderConfigPath = "{0}\App_Config\Include\DataFolder.config" -f $site.physicalPath
			[xml] $dataFolderConfigXML = Get-Content $dataFolderConfigPath
			$dataFolderValue = $dataFolderConfigXML.configuration.sitecore.'sc.variable'.attribute.'#text'
		}
		else
		{
			$dataFolderValue = $dataFolderPath
		}
		$phantomToolPath = "{0}\tools\phantomjs" -f $dataFolderValue
		Remove-Item -Recurse -Path $phantomToolPath

		$downLoadPath = ".\ProtectPhantomJS.config"
		Invoke-WebRequest -Uri $downLoadURI -OutFile $downLoadPath
		Copy-Item -Path $downLoadPath -Destination $rackspaceInclude #we use a "Z.Rackspace" directory under /app_config/include 
	}
	else
	{
		Write-Output "Step 7 skipped as this is a CM instance"
	}

	   Write-Output "Step 7 completed - Protect PhantomJS"

}
else 
{
    Write-Output "Step 7 skipped - Not in stepsStrings variable"
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 8 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Protect Media Requests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if ( $stepsString.Contains("8") )
{
	#set the implementation guid -- the gist just has a placeholder
	$downLoadPath = ".\ProtectMediaRequests.config"
	(Get-Content $downLoadPath).replace($mediaRequestSharedSecretGuid, "58d36579-94c3-42d8-802f-b7cc62121d47") | Set-Content $downLoadPath

	Copy-Item -Path $downLoadPath -Destination $extraInclude 

	Write-Output "Step 8 completed - Protect Media Requests"

}
else 
{
    Write-Output "Step 8 skipped - Not in stepsStrings variable"
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ STEP 9 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Remove header information from responses sent by your website
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

if ( $stepsString.Contains("9") )
{

	$webConfigPath = "{0}\web.config" -f $site.physicalPath
	[xml]$webConfigXML = Get-Content $webConfigPath
	#Remove the X-Aspnet-Version HTTP header
	$webConfigXML.configuration.'system.web'.httpRuntime.SetAttribute("enableVersionHeader","false")
	$webConfigXML.Save($webConfigPath)

	#Remove the X-Powered-By Http header
	$psPath = "MACHINE/WEBROOT/APPHOST/{0}" -f $site.name
	$filter = "system.webServer/httpProtocol/customHeaders"
	Remove-WebConfigurationProperty -PSPath $psPath -Filter $filter -Name . -AtElement @{name='X-Powered-By'}

	#Reminder to apply this one through implementation code

$caveat = @"
	Missing change from the Sitecore recommendations regarding 'Remove the X-AspNetMvc-Version HTTP header'
		-this is an implementation specific element that should come from source control etc
		consider an HTTP Module (instead of Global.asax)
		See the bottom of Akshay Sura's post for details:
			http://www.akshaysura.com/2016/08/02/secure-sitecore-headers-are-a-headache-but-nothing-we-cannot-solve/
	Do not forget this step!
"@

	Write-Host $caveat -ForegroundColor DarkYellow
	
	Write-Output "Step 9 completed - Remove header information from responses sent by your website"

}
else 
{
    Write-Output "Step 9 skipped - Not in stepsStrings variable"
}

Write-Host "Security hardening completed" -ForegroundColor Green