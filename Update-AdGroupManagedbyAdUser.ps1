#requires -version 4
<#
.SYNOPSIS
    Adds user to manged by tab in AD Group properties and check the box Manager can update the membership list.
.DESCRIPTION
    The Update-AdGroupManagedby adds users to group. It asks for parameter as valid CSV file path (Containing Group, User and Domain details), If you want to update muliple group at once, Another option if you don't have CSV file Username, GroupName and Domain name parameter can be used separately. This cmdlet uses AD .net object to perform its task.
.PARAMETER GroupName
    Prompts you valid active directory Group name. You can use first character as an alias, This is mandetory parameter.
.PARAMETER UserName
    Prompts you valid active directory User name. You can use first character as an alias, This is mandetory parameter.
.PARAMETER Domain
    Provide domain netbios name where you User resides.
.PARAMETER CSV
    Provide valid csv file with Groupname, username and domain information.
.INPUTS
    [String]
.OUTPUTS
    Output is on console directly.
.NOTES
    Version:        1.0
    Author:         Kunal Udapi
    Creation Date:  23 August 2017
    Purpose/Change: Manager can update the membership list
    Useful URLs: http://vcloud-lab.com
.EXAMPLE
    PS C:\>Update-AdGroupManagedbyAdUser -Path C:\temp\Groups.csv

    This command update group from CSV file, CSV file contains information Groupname, UserName and Domain.
.Example
    PS C:\>Update-AdGroupManagedbyAdUser -GroupName Group1 -UserName User1 -Domain vcloud-lab
     
    Here I changing information on single Group using parameter
#>
[CmdletBinding(SupportsShouldProcess=$True,
    ConfirmImpact='Medium',
    HelpURI='http://vcloud-lab.com',
    DefaultParameterSetName='Manual')]
Param
(
    [parameter(ParameterSetName = 'Manual', Position=0, Mandatory=$True, ValueFromPipelineByPropertyName=$true)]
    [alias('U')]
    [String]$UserName,
    [Parameter(ParameterSetName='Manual', Position=1, Mandatory=$True)]
    [alias('G')]
    [String]$GroupName,
    [Parameter(ParameterSetName='Manual', Position=2, Mandatory=$True)]
    [String]$Domain,
    [parameter(ParameterSetName = 'CSV', Position=0, Mandatory=$True, ValueFromPipelineByPropertyName=$true)]
    [alias('CSV','File')]
    [String]$Path
)
begin {
    if (!(Get-Module Activedirectory)) {
        Import-Module ActiveDirectory
    }
    #$groupName = 'Group1'
    #$domain = 'vcloud-lab.com'
    #$userName = 'User1'
    switch ($PsCmdlet.ParameterSetName) {
        'Manual' {
            $Obj = New-Object psobject
            $Obj | Add-Member -Name groupName -MemberType NoteProperty -Value $GroupName
            $Obj | Add-Member -Name UserName -MemberType NoteProperty -Value $UserName
            $Obj | Add-Member -Name Domain -MemberType NoteProperty -Value $Domain
            Break
        }
        'CSV' {
            if (Test-Path -Path $Path) {
                $Obj =  Import-Csv -Path $Path
            }
            else {
                Write-Host "$path does not exist" -BackgroundColor DarkRed
            }
            break            
        }
    }
}
process {
    foreach ($O in $Obj) {
        "Working on group '{0}' adding user '{1}'" -f $O.Groupname, $O.Username
        try {
            $group = Get-ADGroup $O.groupName -ErrorAction Stop
        }
        catch {
            Write-Host "$($O.Groupname) does not exist in Active Directory" -BackgroundColor DarkRed
            Continue
        }
        try {
            $u = Get-ADUser $O.userName -ErrorAction Stop
            $UserDN = $u | Select-Object -ExpandProperty DistinguishedName
            #$UserDN
        }
        catch {
            Write-Host "$($O.UserName) does not exist in Active Directory" -BackgroundColor DarkRed
            Continue
        }
        if ($PsCmdlet.ParameterSetName -eq 'CSV') {
            $Domain = $O.Domain
        }
        $DC = ($group.DistinguishedName -split '=')[-1]
        $userAccount = "{0}\{1}" -f $O.domain.ToUpper(), $O.userName
        $rightGuid = Get-ItemProperty "AD:\CN=Self-Membership,CN=Extended-Rights,CN=Configuration,DC=$domain,DC=$DC" -Name rightsGuid | Select-Object -ExpandProperty rightsGuid
        $Guid = [GUID]$rightGuid
        $user = New-Object System.Security.Principal.NTAccount($userAccount)
        $sid = $user.translate([System.Security.Principal.SecurityIdentifier])
        #$group = Get-ADGroup $groupName
        $GroupDN = $group.DistinguishedName
        $acl = Get-Acl AD:\$GroupDN
        $ctrl =[System.Security.AccessControl.AccessControlType]::Allow
        $rights = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
        $intype = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
        #$UserDN = Get-ADUser $userName | Select-Object -ExpandProperty DistinguishedName
        $group = [adsi]"LDAP://$GroupDN"
        $group.put("ManagedBy",$UserDN)
        $group.setinfo()
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid,$rights,$ctrl,$guid)
        $acl.AddAccessRule($rule)
        Set-Acl -acl $acl -path AD:\$GroupDN
        $acl = Get-Acl AD:\$GroupDN
        $access = $acl.Access | Where-Object {$_.IdentityReference -eq $userAccount}
        if ($access -eq $null) {
            Write-Host "Cannot set Manager can not update membership list on Group $($O.Groupname)" -BackgroundColor DarkRed
        }
    }
}
end {}