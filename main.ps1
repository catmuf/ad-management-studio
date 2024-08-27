import-Module ActiveDirectory
$rootPathFolder = $PSScriptRoot

# Get directory containing the main.ps1 script and import necessary modules (views, functions, etc...)
import-Module "$rootPathFolder\Views\viewCreateUser.ps1"
import-Module "$rootPathFolder\Views\viewUser.ps1"
import-Module "$rootPathFolder\Views\viewEditUser.ps1"
import-Module "$rootPathFolder\Views\viewchangePasswordUser.ps1"
import-Module "$rootPathFolder\Views\viewEnableUser.ps1"
import-Module "$rootPathFolder\Views\viewExportOptions.ps1"
import-Module "$rootPathFolder\Functions\viewListUser.ps1"
import-Module "$rootPathFolder\Functions\disableUser.ps1"
import-Module "$rootPathFolder\Functions\Validations.ps1"

# Extract config.conf file and assign key-value pairs in the file as variables
$externalCondig = join-Path $rootPathFolder "\config.conf"
Foreach ($i in $(Get-Content $externalCondig)){
    Set-Variable -Name $i.split("=")[0] -Value $i.split("=",2)[1]
}

# Insert domain name of Windows Server
$domainName = $AD_DOMAIN_NAME

# Path where disabled User must be located
$ADdisableUser = $AD_DISABLE_OU

#Search filters by all AD
$ou = $AD_SEARCH_FILTER

# scriptPath
$ScriptPath = $AD_ScriptPath

# Fie paths of CSVs for displaying dropdowns
$FileDescription = Import-Csv "$rootPathFolder\CSV\Valores Description AD.csv" -Encoding UTF8 | Sort-Object -Property Description
$FileCompany = Import-Csv "$rootPathFolder\CSV\Valores Company AD.csv" -Encoding UTF8 | Sort-Object -Property Company
$FileDepartment = Import-Csv "$rootPathFolder\CSV\Valores Department AD.csv" -Encoding UTF8 | Sort-Object -Property Department
$FileOffice = Import-Csv "$rootPathFolder\CSV\Valores Office AD.csv" -Encoding UTF8 | Sort-Object -Property Office
$FileTitle = Import-Csv "$rootPathFolder\CSV\Valores Title AD.csv" -Encoding UTF8 | Sort-Object -Property Title

# Custom object to hold form-related data
$isOpenObject = [PSCustomObject]@{
    IsOpen = $false
}

# Main view window-----------------------------------------------------------

Add-Type -AssemblyName System.Windows.Forms,PresentationCore,PresentationFramework
[System.Windows.Forms.Application]::EnableVisualStyles()

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = New-Object System.Drawing.Point(750,490)
$Form.text                       = "Gestión de Usuarios"
$Form.TopMost                    = $false
$Form.FormBorderStyle            = "FixedDialog"
$Form.MaximizeBox                = $false

# List of elements in the form ------------------------------------------------------------------

# Boton de Crear
$BotonCrearUsuario               = New-Object system.Windows.Forms.Button
$BotonCrearUsuario.text          = "Crear Usuario"
$BotonCrearUsuario.width         = 100
$BotonCrearUsuario.height        = 30
$BotonCrearUsuario.location      = New-Object System.Drawing.Point(20,20)
$BotonCrearUsuario.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

# Boton de Editar
$BotonEditarUsuario              = New-Object system.Windows.Forms.Button
$BotonEditarUsuario.text         = "Editar Usuario"
$BotonEditarUsuario.width        = 100
$BotonEditarUsuario.height       = 30
$BotonEditarUsuario.location     = New-Object System.Drawing.Point(130,20)
$BotonEditarUsuario.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

# Boton de Baja
$BotonDarBaja                    = New-Object system.Windows.Forms.Button
$BotonDarBaja.text               = "Dar Baja Usuario"
$BotonDarBaja.width              = 120
$BotonDarBaja.height             = 30
$BotonDarBaja.location           = New-Object System.Drawing.Point(240,20)
$BotonDarBaja.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

# Boton de Buscar
$BotonBuscar                      = New-Object system.Windows.Forms.Button
$BotonBuscar.text                 = "Buscar"
$BotonBuscar.width                = 60
$BotonBuscar.height               = 30
$BotonBuscar.location             = New-Object System.Drawing.Point(670,20)
$BotonBuscar.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$TextoBuscador                   = New-Object system.Windows.Forms.TextBox
$TextoBuscador.multiline         = $false
$TextoBuscador.width             = 180
$TextoBuscador.height            = 20
$TextoBuscador.location          = New-Object System.Drawing.Point(480,25)
$TextoBuscador.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

# Boton de Exportar
$BotonExport               = New-Object system.Windows.Forms.Button
$BotonExport.text          = "Exportar"
$BotonExport.width         = 100
$BotonExport.height        = 30
$BotonExport.location      = New-Object System.Drawing.Point(20,70)
$BotonExport.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

# Listview panel
$ListaUsuarios                   = New-Object system.Windows.Forms.ListView
$ListaUsuarios.width             = 711
$ListaUsuarios.height            = 361
$ListaUsuarios.location          = New-Object System.Drawing.Point(20,110)
$ListaUsuarios.View = [Windows.Forms.View]::Details
$ListaUsuarios.Columns.Add("Nombre", 120)
$ListaUsuarios.Columns.Add("DNI/NIE", 80)
$ListaUsuarios.Columns.Add("Correo", 130)
$ListaUsuarios.Columns.Add("Descrpición",120)
$ListaUsuarios.Columns.Add("Departamento", 120)
$ListaUsuarios.Columns.Add("Oficina",120)
$ListaUsuarios.FullRowSelect = $true
$ListaUsuarios.GridLines = $true
$ListaUsuarios.Sorting = [Windows.Forms.SortOrder]::Ascending

# Create a ContextMenuStrip for listview 
$contextMenu = New-Object Windows.Forms.ContextMenuStrip

# Add menu items
$menuItem1 = $contextMenu.Items.Add("Ver")
$menuItem2 = $contextMenu.Items.Add("Editar")
$menuItem3 = $contextMenu.Items.Add("Cambiar Clave")
$menuItem4 = $contextMenu.Items.Add("Dar Baja")
$menuItem5 = $contextMenu.Items.Add("Habilitar")

# Assign the ContextMenuStrip to the ListView
$ListaUsuarios.ContextMenuStrip = $contextMenu

# Add elements to the form
$Form.controls.AddRange(@($BotonCrearUsuario,$BotonEditarUsuario,$BotonDarBaja,$TextoBuscador,$BotonBuscar,$BotonExport,$ListaUsuarios))

#------------------------------------------------------------------------------------------------


# Create user Button
$BotonCrearUsuario.Add_Click({ 
    CreateUser
})

# Edit user Button
$BotonEditarUsuario.Add_Click({ 
    # Checks if item is selected in listview
    if ($ListaUsuarios.SelectedItems[0] -eq $null) {
        #Pop up window
        $ButtonType = [System.Windows.MessageBoxButton]::Ok
        $MessageIcon = [System.Windows.MessageBoxImage]::Error
        $MessageBody = "Seleccione un usuario!"
        $MessageTitle = "Error"
        [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
    } else {
        $selectedUser = $ListaUsuarios.SelectedItems[0]
        EditUser -identity $selectedUser.Tag -WindowState $isOpenObject
    }
})

# Unregister User Button
$BotonDarBaja.Add_Click({
    # Checks if item is selected in listview 
    if ($ListaUsuarios.SelectedItems[0] -eq $null) {
        $ButtonType = [System.Windows.MessageBoxButton]::Ok
        $MessageIcon = [System.Windows.MessageBoxImage]::Error
        $MessageBody = "Seleccione un usuario!"
        $MessageTitle = "Error"
        [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
    } else {
        $selectedUser = $ListaUsuarios.SelectedItems[0]
        $identityName = $selectedUser.Text
        $identityID = $selectedUser.SubItems[1].Text
        $ButtonType = [System.Windows.MessageBoxButton]::OkCancel
        $MessageIcon = [System.Windows.MessageBoxImage]::Warning
        $MessageBody = "¿Estás seguro de que quieres deshabilitar el usuario $identityName ($identityID)?"
        $MessageTitle = "Warning"
        $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
    
        if($Result -ceq "Ok") {
            $selectedUser = $ListaUsuarios.SelectedItems[0]
            DisableUser -identity $selectedUser.Tag
            (viewlistUser -keywords $TextoBuscador.Text -activateSearch $true)
        } 
    }
})

# 'Enter' key for search
$TextoBuscador.Add_KeyDown({
    if ($_.KeyCode -eq 'Enter') {
        $BotonBuscar.PerformClick()
    }
})

# Search button
$BotonBuscar.Add_Click({
    viewlistUser -keywords $TextoBuscador.Text -activateSearch $true
   
})

$BotonExport.Add_Click({
    exportOptions -rootPathFolder $rootPathFolder
})

# Sorting list for first column "Name"
$ListaUsuarios.Add_ColumnClick({
    param ($sender, $e)

    # Set the sorting column and order
    if ($e.Column -eq 0) {
        if ($ListaUsuarios.Sorting -eq [Windows.Forms.SortOrder]::Ascending) {
            $ListaUsuarios.Sorting = [Windows.Forms.SortOrder]::Descending
        } else {
            $ListaUsuarios.Sorting = [Windows.Forms.SortOrder]::Ascending
        }
    }

    # Perform the sort based on the clicked column
    $ListaUsuarios.Sort()
})

# Double Click action to show user´s informaiton
$ListaUsuarios.Add_DoubleClick({
    # Function to be invoked on double-click
    $selectedUser = $ListaUsuarios.SelectedItems[0]
    viewUser -identity $selectedUser.Tag
})

# Menu´s items in viewlist panel----------------------------------------------------------------------------------------------------------

# Item view user´s information
$menuItem1.Add_Click({
    if ($ListaUsuarios.SelectedItems[0] -eq $null) {
        $ButtonType = [System.Windows.MessageBoxButton]::Ok
        $MessageIcon = [System.Windows.MessageBoxImage]::Error
        $MessageBody = "Seleccione un usuario!"
        $MessageTitle = "Error"
        [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
    } else {
        $selectedUser = $ListaUsuarios.SelectedItems[0]
        viewUser -identity $selectedUser.Tag
    }
})

# Item Edit user´s information
$menuItem2.Add_Click({
    $BotonEditarUsuario.PerformClick()
})

# Item change user´s password
$menuItem3.Add_Click({
    if ($ListaUsuarios.SelectedItems[0] -eq $null) {
        $ButtonType = [System.Windows.MessageBoxButton]::Ok
        $MessageIcon = [System.Windows.MessageBoxImage]::Error
        $MessageBody = "Seleccione un usuario!"
        $MessageTitle = "Error"
        [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
    } else {
        $selectedUser = $ListaUsuarios.SelectedItems[0]
        $identityName = $selectedUser.Text
        $identityID = $selectedUser.SubItems[1].Text
        ChangePassword -identity $selectedUser.Tag -identityName $identityName -identityID $identityID
        (viewlistUser -keywords $TextoBuscador.Text -activateSearch $true)
    }
})

# Item disable user
$menuItem4.Add_Click({
    $BotonDarBaja.PerformClick()
})

# Item enable user
$menuItem5.Add_Click({
     if ($ListaUsuarios.SelectedItems[0] -eq $null) {
        $ButtonType = [System.Windows.MessageBoxButton]::Ok
        $MessageIcon = [System.Windows.MessageBoxImage]::Error
        $MessageBody = "Seleccione un usuario!"
        $MessageTitle = "Error"
        [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
    } else {
        $selectedUser = $ListaUsuarios.SelectedItems[0]
        viewEnableUser -identity $selectedUser.Tag
    }
})

#----------------------------------------------------------------------------------------------------------

#region Logic 

#endregion

[void]$Form.ShowDialog()