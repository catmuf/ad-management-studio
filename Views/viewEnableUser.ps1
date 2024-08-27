function viewEnableUser{
    <# 
    .NAME
        Enable User
    #>
    param(
        $identity
    )

    $getUser = Get-ADUser -Identity $identity -Properties *
    $fullName = $getUser.Name
    $ID = $getUser.EmployeeID

    $fullDistinguishedName = $identityDN
    $fullDistinguishedNameParts = $fullDistinguishedName -split "," | Select-Object -Skip 1
    $DNString = $fullDistinguishedNameParts -join ','

    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $Form                            = New-Object system.Windows.Forms.Form
    $Form.ClientSize                 = New-Object System.Drawing.Point(500,180)
    $Form.text                       = "Habilitar Usuario"
    $Form.TopMost                    = $false

    $LblNombre                          = New-Object system.Windows.Forms.Label
    $LblNombre.text                     = "$fullName ($ID)"
    $LblNombre.AutoSize                 = $true
    $LblNombre.width                    = 25
    $LblNombre.height                   = 10
    $LblNombre.location                 = New-Object System.Drawing.Point(30,20)
    $LblNombre.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblMoveOU                          = New-Object system.Windows.Forms.Label
    $LblMoveOU.text                     = "Mover a:"
    $LblMoveOU.AutoSize                 = $true
    $LblMoveOU.width                    = 25
    $LblMoveOU.height                   = 10
    $LblMoveOU.location                 = New-Object System.Drawing.Point(30,55)
    $LblMoveOU.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $ListOU                       = New-Object system.Windows.Forms.ComboBox
    $ListOU.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListOU.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListOU.width                 = 440
    $ListOU.height                = 20
    $ListOU.location              = New-Object System.Drawing.Point(30,90)
    $ListOU.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $Aceptar                         = New-Object system.Windows.Forms.Button
    $Aceptar.text                    = "Aceptar"
    $Aceptar.width                   = 60
    $Aceptar.height                  = 30
    $Aceptar.location                = New-Object System.Drawing.Point(225,130)
    $Aceptar.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $Form.controls.AddRange(@($LblNombre,$LblMoveOU,$ListOU,$Aceptar))

	# Get all OU by organizationalUnit and sorted in asc
    $ListAD = Get-ADObject -LDAPFilter 'objectclass=organizationalUnit' -Properties * | 
    Where-Object { $_.objectclass -in 'organizationalUnit' } | 
    Sort-Object canonicalName, DistinguishedName
    
    $ExtractPathName = @{}
    # Renaming canonicalName which ignores the first path
	# Example test.local/Habilitados/Test, takes out test.local/ and output Habilitados/Test
    foreach ($ADFolder in $ListAD){
        $splitPath = $ADFolder.canonicalName -split '/' | Select-Object -Skip 1
        $OUString = $splitPath -join '/'
        $ExtractPathName[$OUString] = $ADFolder.DistinguishedName
    }
    
	# Add to listview
    $OrderedHashAD = $ExtractPathName.GetEnumerator() | Sort-Object -Property Name
    foreach($item in $OrderedHashAD) {
        $ListOU.Items.Add($item.Name)
    }
	
	# Add a row for -- Seleccionar OU -- in the first place
    $ListOU.Add_DrawItem(
        {param($sender,$e)
        $text = "-- Seleccionar OU --"
        if ($e.Index -gt -1){
            $text = $sender.GetItemText($sender.Items[$e.Index])
        }
        $e.DrawBackground()
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $text, $combo.Font, `
            $e.Bounds, $e.ForeColor, [System.Windows.Forms.TextFormatFlags]::Default)
    })

	# After clicking confirm
    $Aceptar.Add_Click({
		# pop up message
        $ButtonType = [System.Windows.MessageBoxButton]::OkCancel
        $MessageIcon = [System.Windows.MessageBoxImage]::Warning
        $MessageBody = "¿Estás seguro de que quieres habilitar el usuario $fullName ($ID)?"
        $MessageTitle = "Warning"
        $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
    
        if($Result -ceq "Ok") {
            $selectedDN = $ListOU.SelectedItem
            $idDN = $ExtractPathName[$selectedDN]

            # User´s SID
            Enable-ADAccount -Identity $identity
			# Move user to an specific OU
            Move-ADObject -Identity $identity -TargetPath $idDN
            $ButtonType = [System.Windows.MessageBoxButton]::Ok
            $MessageIcon = [System.Windows.MessageBoxImage]::Information
            $MessageBody = "Usuario habilitado y movido a $selectedDN"
            $MessageTitle = "Información"
            [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
			(viewlistUser -keywords $TextoBuscador.Text -activateSearch $true)
            $Form.Close()
        }
    })

    [void]$Form.ShowDialog()
}