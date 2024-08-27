function viewlistUser {

    # Optional parameters
    param(
        $keywords,
        $activateSearch
    )

    # Clear viewlist table
    $ListaUsuarios.Items.Clear()
    
    # Search users
    if ($activateSearch -eq $true -and !($keywords -eq $null -or $keywords -eq "")) {
        # Clear any white spaces both sides
        $keywords = $keywords.trim()

        $keywords = "*" + $keywords + "*"
        # For each search by ou, it will be added to variable users
        $users = Get-ADUser -Filter {(Name -like $keywords) -or (EmployeeID -like $keywords) -or (userPrincipalName -like $keywords)} -SearchBase $ou -Properties * |
                 Select-Object Name, EmployeeID, Mail, Description, Department, Office, SID, DistinguishedName, UserAccountControl, ObjectGUID
        
        # Create a list to store ListViewItem objects
        $items = @()

        # Every item has its own unique tag and DistinguishedName, in case of editing a specific user when selected
        foreach ($user in $users) {
            if(![string]::IsNullOrWhiteSpace($user.Name)) {
                $item = New-Object Windows.Forms.ListViewItem($user.Name)
            } else{
                $item = New-Object Windows.Forms.ListViewItem("")
            }

            if(![string]::IsNullOrWhiteSpace($user.EmployeeID)) {
                $item.SubItems.Add($user.EmployeeID)
            } else {
                $item.SubItems.Add("")
            }

            if(![string]::IsNullOrWhiteSpace($user.Mail)) {
                $item.SubItems.Add($user.Mail)
            } else {
                $item.SubItems.Add("")
            }

            if(![string]::IsNullOrWhiteSpace($user.Description)) {
                $item.SubItems.Add($user.Description)
            } else {
                $item.SubItems.Add("")
            }

            if(![string]::IsNullOrWhiteSpace($user.Department)) {
                $item.SubItems.Add($user.Department)
            } else {
                $item.SubItems.Add("")
            }

            if(![string]::IsNullOrWhiteSpace($user.Office)) {
                $item.SubItems.Add($user.Office)
            } else {
                $item.SubItems.Add("")
            }

            # Turns item to grey as inactive user
            if($user.UserAccountControl -eq 514) {
                $item.ForeColor = [System.Drawing.Color]::Gray
            }
            $item.Tag = $user.ObjectGUID

            # Add the ListViewItem to the list
            $items += $item
        }

        # Add all items to the ListView in one go
        return $ListaUsuarios.Items.AddRange($items)
    }
}