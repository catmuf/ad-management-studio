# CSV Exportation function
function exportOptions{
    <# 
    .NAME
        Export options
    #>
    param(
        $rootPathFolder
    )

    #Capture latest date
    $DST = Get-Date
    $DateStr = $DST.ToString("dd-MM-yyyy HH-mm")

    # Set the default path
    $downloadsPath = [System.IO.Path]::Combine($env:USERPROFILE, 'Downloads')
    # Predefined naming scheme
    $defaultPath = [System.IO.Path]::Combine($downloadsPath, "nombre $DateStr.csv")

    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $Form                            = New-Object system.Windows.Forms.Form
    $Form.ClientSize                 = New-Object System.Drawing.Point(550,100)
    $Form.text                       = "Exportar a CSV"
    $Form.TopMost                    = $false
    $Form.FormBorderStyle            = "FixedDialog"
    $Form.MaximizeBox                = $false

    $textPath                   = New-Object system.Windows.Forms.TextBox
    $textPath.multiline         = $false
    $textPath.width             = 400
    $textPath.height            = 20
    $textPath.location          = New-Object System.Drawing.Point(20, 10)
    $textPath.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $textPath.Text              = $defaultPath  # Set the default path

    $BtnChangePath                        = New-Object system.Windows.Forms.Button
    $BtnChangePath.text                   = "Cambiar ruta"
    $BtnChangePath.width                  = 100
    $BtnChangePath.height                 = 25
    $BtnChangePath.location               = New-Object System.Drawing.Point(430,10)
    $BtnChangePath.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $Option_1                        = New-Object system.Windows.Forms.Button
    $Option_1.text                   = "Hosp. Manises `ny Centro de Especialidades"
    $Option_1.width                  = 180
    $Option_1.height                 = 40
    $Option_1.location               = New-Object System.Drawing.Point(20,50)
    $Option_1.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $Option_2                        = New-Object system.Windows.Forms.Button
    $Option_2.text                   = "Primaria"
    $Option_2.width                  = 120
    $Option_2.height                 = 40
    $Option_2.location               = New-Object System.Drawing.Point(210,50)
    $Option_2.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $Option_3                        = New-Object system.Windows.Forms.Button
    $Option_3.text                   = "Todos"
    $Option_3.width                  = 80
    $Option_3.height                 = 40
    $Option_3.location               = New-Object System.Drawing.Point(340,50)
    $Option_3.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $Form.controls.AddRange(@($textPath,$BtnChangePath,$Option_1,$Option_2,$Option_3))

    $BtnChangePath.Add_Click({
        # Get latest date
        $DST = Get-Date
        # Dat format and time
        $DateStr = $DST.ToString("dd-MM-yyyy HH-mm")
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        # Deafault name with date & time
        $saveFileDialog.FileName = "nombre $DateStr"
        # Serch filter and default save extension format
        $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv"
        $saveFileDialog.DefaultExt = "csv"

        # Ok confirmation
        if ($saveFileDialog.ShowDialog() -eq 'OK') {
            # Update full file path and filename included
            $filePath = $saveFileDialog.FileName
            $textPath.Text = $filePath
        }
    })

    # --------------------------------------------- Exportation Options -------------------------------------------------------
    $Option_1.Add_Click({
        # Specific OU
        $OUs = Get-Content "$rootPathFolder\config\AD Hosp. Manises y Centro de Especialidades.txt" -Encoding UTF8
        
        $filePath = $textPath.Text

        $users = @()
        # Iteration each OUs
        foreach ($ou in $OUs) {
            $usersInOU = Get-ADUser -Filter * -SearchBase $ou -Properties * | Select-Object Name, UserPrincipalName, EmployeeID, Mail, Title, Company, Description, Created, Modified | Sort-Object -Property Name
            # Adds new users in current users
            $users += $usersInOU
        }

        # Check if the directory exists
        if (-not [string]::IsNullOrWhiteSpace($filePath)) {
            $directory = [System.IO.Path]::GetDirectoryName($filePath)

            if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -Path $directory)) {
                $ButtonType = [System.Windows.MessageBoxButton]::Ok
                $MessageIcon = [System.Windows.MessageBoxImage]::Error
                $MessageBody = "El directorio especificado no existe. Indique un directorio válido."
                $MessageTitle = "Error"
                $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
                
            } else {
                # Export to CSV with delimiter ; and UTF-8 encoding
                $users | Export-Csv -Path $filePath -NoTypeInformation -Delimiter ";" -Encoding UTF8
                
                # Pop up success message 
                $ButtonType = [System.Windows.MessageBoxButton]::Ok
                $MessageIcon = [System.Windows.MessageBoxImage]::Information
                $MessageBody = "La exportación se hizo correctamente. `nGuardado en $filePath"
                $MessageTitle = "Exportado"
                $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
            }

        } else {
            $ButtonType = [System.Windows.MessageBoxButton]::Ok
            $MessageIcon = [System.Windows.MessageBoxImage]::Error
            $MessageBody = "Proporcione una ruta de archivo válida."
            $MessageTitle = "Error"
            $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
        }
     })

    $Option_2.Add_Click({
        # Specific OU
        $OUs = Get-Content -path "$rootPathFolder\config\AD Primaria.txt" -Encoding UTF8 

        $filePath = $textPath.Text
        $users = @()
        # Search and adds to users
        foreach ($ou in $OUs) {
            $usersInOU = Get-ADUser -Filter * -SearchBase $ou -Properties * | Select-Object Name, UserPrincipalName, EmployeeID, Mail, Title, Company, Description, Created, Modified | Sort-Object -Property Name
            # Adds new users in current users 
            $users += $usersInOU
        }

        # Check if the directory exists
        if (-not [string]::IsNullOrWhiteSpace($filePath)) {
            $directory = [System.IO.Path]::GetDirectoryName($filePath)

            if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -Path $directory)) {
                $ButtonType = [System.Windows.MessageBoxButton]::Ok
                $MessageIcon = [System.Windows.MessageBoxImage]::Error
                $MessageBody = "El directorio especificado no existe. Indique un directorio válido."
                $MessageTitle = "Error"
                $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
            } else {

                # Export to CSV with delimiter ; and UTF-8 encoding
                $users | Export-Csv -Path $filePath -NoTypeInformation -Delimiter ";" -Encoding UTF8
                
                # Pop up success message 
                $ButtonType = [System.Windows.MessageBoxButton]::Ok
                $MessageIcon = [System.Windows.MessageBoxImage]::Information
                $MessageBody = "La exportación se hizo correctamente. `nGuardado en $filePath"
                $MessageTitle = "Exportado"
                $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
            }
        } else {
            $ButtonType = [System.Windows.MessageBoxButton]::Ok
            $MessageIcon = [System.Windows.MessageBoxImage]::Error
            $MessageBody = "Proporcione una ruta de archivo válida."
            $MessageTitle = "Error"
            $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
        }
    })

    $Option_3.Add_Click({ 
        # Array of OUs
        $OUs = Get-Content -path "$rootPathFolder\config\AD Todos.txt" -Encoding UTF8 

		$filePath = $textPath.Text
        $users = @()
        # Iteration each OUs
        foreach ($ou in $OUs) {
            $usersInOU = Get-ADUser -Filter * -SearchBase $ou -Properties * | Select-Object Name, UserPrincipalName, EmployeeID, Mail, Title, Company, Description, Created, Modified | Sort-Object -Property Name
            # Adds new users in current users 
            $users += $usersInOU
        }

        # Check if the directory exists
        if (-not [string]::IsNullOrWhiteSpace($filePath)) {
            $directory = [System.IO.Path]::GetDirectoryName($filePath)

            if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -Path $directory)) {
                $ButtonType = [System.Windows.MessageBoxButton]::Ok
                $MessageIcon = [System.Windows.MessageBoxImage]::Error
                $MessageBody = "El directorio especificado no existe. Indique un directorio válido."
                $MessageTitle = "Error"
                $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
                return
            } else {
                # Export to CSV with delimiter ; and UTF-8 encoding
                $users | Export-Csv -Path $filePath -NoTypeInformation -Delimiter ";" -Encoding UTF8
                # Pop up success message 
                $ButtonType = [System.Windows.MessageBoxButton]::Ok
                $MessageIcon = [System.Windows.MessageBoxImage]::Information
                $MessageBody = "La exportación se hizo correctamente. `nGuardado en $filePath"
                $MessageTitle = "Exportado"
                $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
            }

            $users | Export-Csv -Path $filePath -NoTypeInformation -Delimiter ";" -Encoding UTF8
        } else {
            $ButtonType = [System.Windows.MessageBoxButton]::Ok
            $MessageIcon = [System.Windows.MessageBoxImage]::Error
            $MessageBody = "Proporcione una ruta de archivo válida."
            $MessageTitle = "Error"
            $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
        }
     }) 
    # -----------------------------------------------------------------------------------------------------------------------------

    [void]$Form.ShowDialog()
}