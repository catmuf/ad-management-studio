# --------------------------------------------- Edit user view function ------------------------------------------------------
function EditUser {
    param (
        $identity,
        [psobject]$WindowState
    )

    # Extracts All user´s Properties by SID
    $getUser = Get-ADUser -Identity $identity -Properties *
    $Actualnombre = $getUser.givenName
    $Actualapellidos = $getUser.Surname
    $Actualid = $getUser.EmployeeID
    $Actualusuario = $getUser.UserPrincipalName
    $Actualemail = $getUser.mail
    #$Actualpassword = $getUser.AccountPassword
    $Actualdescription = $getUser.Description
    $Actualoffice = $getUser.Office
    $Actualtitle = $getUser.Title
    $Actualdepartment = $getUser.Department
    $Actualcompany = $getUser.Company
    $ActualDN = $getUser.distinguishedName
    $DropdownHeight = 250

    $State = [PSCustomObject]@{
        Name = $false
        Surname = $false
        ID = $false
        Username = $false
        Email = $false
        Description = $false
        Office = $false
        Title = $false
        Department = $false
        Company = $false
        OU = $false
    }

    $fullUsername = $Actualusuario
    $fullNameParts = $fullUsername -split "@"
    $username = $fullNameParts[0]

    $fullDistinguishedName = $ActualDN
    $fullDistinguishedNameParts = $fullDistinguishedName -split "," | Select-Object -Skip 1
    $DNString = $fullDistinguishedNameParts -join ','
    
     
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # --------------------------------------------- List of elements in the form --------------------------------------------------------------
    $Form                            = New-Object system.Windows.Forms.Form
    $Form.ClientSize                 = New-Object System.Drawing.Point(700,650)
    $Form.text                       = "Editar Usuario"
    $Form.TopMost                    = $false
    $Form.FormBorderStyle            = "FixedDialog"
    $Form.MaximizeBox                = $false
    
    # Nombre
    $TBNombre                        = New-Object system.Windows.Forms.TextBox
    $TBNombre.multiline              = $false
    $TBNombre.width                  = 200
    $TBNombre.height                 = 20
    $TBNombre.location               = New-Object System.Drawing.Point(135,20)
    $TBNombre.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBNombre.Text = $Actualnombre

    $SMSNombre                       = New-Object system.Windows.Forms.Label
    $SMSNombre.AutoSize              = $true
    $SMSNombre.height                = 10
    $SMSNombre.location              = New-Object System.Drawing.Point(135,45)
    $SMSNombre.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblNombre                       = New-Object system.Windows.Forms.Label
    $LblNombre.text                  = "Nombre:"
    $LblNombre.AutoSize              = $true
    $LblNombre.width                 = 25
    $LblNombre.height                = 10
    $LblNombre.location              = New-Object System.Drawing.Point(20,20)
    $LblNombre.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Apellidos
    $TBApellidos                        = New-Object system.Windows.Forms.TextBox
    $TBApellidos.multiline              = $false
    $TBApellidos.width                  = 200
    $TBApellidos.height                 = 20
    $TBApellidos.location               = New-Object System.Drawing.Point(135,70)
    $TBApellidos.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBApellidos.Text = $Actualapellidos

    $SMSApellidos                       = New-Object system.Windows.Forms.Label
    $SMSApellidos.AutoSize              = $true
    $SMSApellidos.height                = 10
    $SMSApellidos.location              = New-Object System.Drawing.Point(135,95)
    $SMSApellidos.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblApellidos                    = New-Object system.Windows.Forms.Label
    $LblApellidos.text               = "Apellidos:"
    $LblApellidos.AutoSize           = $true
    $LblApellidos.width              = 25
    $LblApellidos.height             = 10
    $LblApellidos.location           = New-Object System.Drawing.Point(20,70)
    $LblApellidos.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # ID
    $TBID                        = New-Object system.Windows.Forms.TextBox
    $TBID.multiline              = $false
    $TBID.width                  = 150
    $TBID.height                 = 20
    $TBID.location               = New-Object System.Drawing.Point(135,120)
    $TBID.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBID.text = $Actualid

    $SMSID                       = New-Object system.Windows.Forms.Label
    $SMSID.AutoSize              = $true
    $SMSID.width                 = 25
    $SMSID.height                = 10
    $SMSID.location              = New-Object System.Drawing.Point(135,145)
    $SMSID.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',8)

    $LblID                       = New-Object system.Windows.Forms.Label
    $LblID.text                  = "DNI/NIE:"
    $LblID.AutoSize              = $true
    $LblID.width                 = 25
    $LblID.height                = 10
    $LblID.location              = New-Object System.Drawing.Point(20,120)
    $LblID.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Usuario
    $TBUsuario                        = New-Object system.Windows.Forms.TextBox
    $TBUsuario.multiline              = $false
    $TBUsuario.width                  = 200
    $TBUsuario.height                 = 20
    $TBUsuario.location               = New-Object System.Drawing.Point(135,170)
    $TBUsuario.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBUsuario.text = $username

    $SMSUsuario                       = New-Object system.Windows.Forms.Label
    $SMSUsuario.AutoSize              = $true
    $SMSUsuario.height                = 10
    $SMSUsuario.location              = New-Object System.Drawing.Point(135,195)
    $SMSUsuario.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblUsuario                       = New-Object system.Windows.Forms.Label
    $LblUsuario.text                  = "Usuario:"
    $LblUsuario.AutoSize              = $true
    $LblUsuario.width                 = 25
    $LblUsuario.height                = 10
    $LblUsuario.location              = New-Object System.Drawing.Point(20,170)
    $LblUsuario.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Domain
    $LblDomain                       = New-Object system.Windows.Forms.Label
    $LblDomain.text                  = $domainName
    $LblDomain.AutoSize              = $true
    $LblDomain.width                 = 25
    $LblDomain.height                = 10
    $LblDomain.location              = New-Object System.Drawing.Point(350,170)
    $LblDomain.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    # Email
    $TBEmail                        = New-Object system.Windows.Forms.TextBox
    $TBEmail.multiline              = $false
    $TBEmail.width                  = 200
    $TBEmail.height                 = 20
    $TBEmail.location               = New-Object System.Drawing.Point(135,220)
    $TBEmail.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    
    $SMSEmail                       = New-Object system.Windows.Forms.Label
    $SMSEmail.AutoSize              = $true
    $SMSEmail.height                = 10
    $SMSEmail.location              = New-Object System.Drawing.Point(135,245)
    $SMSEmail.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblEmail                       = New-Object system.Windows.Forms.Label
    $LblEmail.Text                  = "Correo externo:"
    $LblEmail.AutoSize              = $true
    $LblEmail.width                 = 25
    $LblEmail.height                = 10
    $LblEmail.location              = New-Object System.Drawing.Point(20,220)
    $LblEmail.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    
    # Create checkbox to toggle Email input visibility
    $CBEmail                          = New-Object System.Windows.Forms.CheckBox
    $CBEmail.Text                     = "Añadir correo"
    $CBEmail.location                 = New-Object System.Drawing.Point(350,220)

    # Description
    $ListDescription                        = New-Object system.Windows.Forms.ComboBox
    $ListDescription.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListDescription.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListDescription.autosize               = $true
    $ListDescription.Size                   = New-Object System.Drawing.Size(400, 20)
    $ListDescription.location               = New-Object System.Drawing.Point(135,270)
    $ListDescription.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ListDescription.DropDownHeight         = $DropdownHeight

    $SMSDescription                       = New-Object system.Windows.Forms.Label
    $SMSDescription.AutoSize              = $true
    $SMSDescription.height                = 10
    $SMSDescription.location              = New-Object System.Drawing.Point(135,295)
    $SMSDescription.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblDescription                       = New-Object system.Windows.Forms.Label
    $LblDescription.text                  = "Descripción:"
    $LblDescription.AutoSize              = $true
    $LblDescription.width                 = 25
    $LblDescription.height                = 10
    $LblDescription.location              = New-Object System.Drawing.Point(20,270)
    $LblDescription.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Office
    $ListOffice                        = New-Object system.Windows.Forms.ComboBox
    $ListOffice.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListOffice.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListOffice.autosize               = $true
    $ListOffice.Size                   = New-Object System.Drawing.Size(400, 20)
    $ListOffice.location               = New-Object System.Drawing.Point(135,320)
    $ListOffice.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ListOffice.DropDownHeight          = $DropdownHeight

    $SMSOffice                       = New-Object system.Windows.Forms.Label
    $SMSOffice.AutoSize              = $true
    $SMSOffice.height                = 10
    $SMSOffice.location              = New-Object System.Drawing.Point(135,345)
    $SMSOffice.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblOffice                       = New-Object system.Windows.Forms.Label
    $LblOffice.text                  = "Oficina:"
    $LblOffice.AutoSize              = $true
    $LblOffice.width                 = 25
    $LblOffice.height                = 10
    $LblOffice.location              = New-Object System.Drawing.Point(20,320)
    $LblOffice.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    # Title
    $ListTitle                        = New-Object system.Windows.Forms.ComboBox
    $ListTitle.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListTitle.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListTitle.autosize               = $true
    $ListTitle.Size                   = New-Object System.Drawing.Size(400, 20)
    $ListTitle.location               = New-Object System.Drawing.Point(135,370)
    $ListTitle.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ListTitle.DropDownHeight           = $DropdownHeight

    $SMSTitle                       = New-Object system.Windows.Forms.Label
    $SMSTitle.AutoSize              = $true
    $SMSTitle.height                = 10
    $SMSTitle.location              = New-Object System.Drawing.Point(135,395)
    $SMSTitle.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblTitle                       = New-Object system.Windows.Forms.Label
    $LblTitle.text                  = "Título:"
    $LblTitle.AutoSize              = $true
    $LblTitle.width                 = 25
    $LblTitle.height                = 10
    $LblTitle.location              = New-Object System.Drawing.Point(20,370)
    $LblTitle.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Department
    $ListDepartment                        = New-Object system.Windows.Forms.ComboBox
    $ListDepartment.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListDepartment.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListDepartment.autosize               = $true
    $ListDepartment.Size                   = New-Object System.Drawing.Size(400, 20)
    $ListDepartment.location               = New-Object System.Drawing.Point(135,420)
    $ListDepartment.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ListDepartment.DropDownHeight          = $DropdownHeight

    $SMSDepartment                       = New-Object system.Windows.Forms.Label
    $SMSDepartment.AutoSize              = $true
    $SMSDepartment.height                = 10
    $SMSDepartment.location              = New-Object System.Drawing.Point(135,445)
    $SMSDepartment.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblDepartment                       = New-Object system.Windows.Forms.Label
    $LblDepartment.text                  = "Departamento:"
    $LblDepartment.AutoSize              = $true
    $LblDepartment.width                 = 25
    $LblDepartment.height                = 10
    $LblDepartment.location              = New-Object System.Drawing.Point(20,420)
    $LblDepartment.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Company
    $ListCompany                        = New-Object system.Windows.Forms.ComboBox
    $ListCompany.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListCompany.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListCompany.Size                   = New-Object System.Drawing.Size(400, 20)
    $ListCompany.location               = New-Object System.Drawing.Point(135,470)
    $ListCompany.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ListCompany.DropDownHeight         = $DropdownHeight
    $SMSCompany                       = New-Object system.Windows.Forms.Label
    $SMSCompany.AutoSize              = $true
    $SMSCompany.height                = 10
    $SMSCompany.location              = New-Object System.Drawing.Point(135,495)
    $SMSCompany.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblCompany                       = New-Object system.Windows.Forms.Label
    $LblCompany.text                  = "Companía:"
    $LblCompany.AutoSize              = $true
    $LblCompany.width                 = 25
    $LblCompany.height                = 10
    $LblCompany.location              = New-Object System.Drawing.Point(20,470)
    $LblCompany.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # OU list
    $LblOU                       = New-Object system.Windows.Forms.Label
    $LblOU.text                  = "OU:"
    $LblOU.AutoSize              = $true
    $LblOU.width                 = 25
    $LblOU.height                = 10
    $LblOU.location              = New-Object System.Drawing.Point(20,520)
    $LblOU.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $ListOU                        = New-Object system.Windows.Forms.ComboBox
    $ListOU.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListOU.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListOU.Size                   = New-Object System.Drawing.Size(650, 20)
    $ListOU.location               = New-Object System.Drawing.Point(20,540)
    $ListOU.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',9)
    $ListOU.DropDownHeight = $DropdownHeight

    $SMSOU                       = New-Object system.Windows.Forms.Label
    $SMSOU.AutoSize              = $true
    $SMSOU.height                = 10
    $SMSOU.location              = New-Object System.Drawing.Point(20,565)
    $SMSOU.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    # Aceptar
    $BotonAceptar                    = New-Object system.Windows.Forms.Button
    $BotonAceptar.text               = "Aceptar"
    $BotonAceptar.width              = 60
    $BotonAceptar.height             = 30
    $BotonAceptar.location           = New-Object System.Drawing.Point(250,600)
    $BotonAceptar.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $BotonAceptar.Enabled            = $false

    # Create a ToolTips
    $toolTipID = New-Object Windows.Forms.ToolTip
    $toolTipID.SetToolTip($TBID, "DNI: 8 números y una letra en mayúscula `nNIE: Letra X, Y o Z, 7 números y una letra en mayúscula")

    # ----------------------------------------------------------------- Add buttons in form----------------------------------------------------------------------

    $Form.controls.AddRange(@($TBNombre,$SMSNombre,$LblNombre,$TBApellidos,$SMSApellidos,$LblApellidos,$TBID,$SMSID,$LblID,$LblUsuario,$TBUsuario,$SMSUsuario,$LblDomain, `
                            $LblEmail,$TBEmail,$SMSEmail,$CBEmail,$LblDescription,$ListDescription,$SMSDescription,$LblOffice,$ListOffice,$SMSOffice,$LblTitle,$ListTitle,$SMSTitle, `
                            $LblDepartment,$ListDepartment,$SMSDepartment,$LblCompany,$ListCompany,$SMSCompany,$LblOU,$ListOU,$SMSOU,$BotonAceptar))

    # -----------------------------------------------------------------------------------------------------------------------------------------------------------
    
    if([string]::IsNullOrWhiteSpace($Actualemail)) {
        $CBEmail.Checked                = $false
        $TBEmail.Enabled                = $false
    } else {
        $CBEmail.Checked                = $true
        $TBEmail.Enabled                = $true
        $TBEmail.Text                   = $Actualemail
    }

    #When form is opened
    $Form.Add_Shown({
        # Set the window state to open
        $WindowState.IsOpen = $true

    })

    # ----------------------------------------------- Add items to the dropdown list ------------------------------------------------------
    foreach ($item in $FileDescription) {
        $ListDescription.Items.Add($item.Description.Trim())
    }

    foreach ($item in $FileCompany) {
        $ListCompany.Items.Add($item.Company.Trim())
    }

    foreach ($item in $FileDepartment) {
        $ListDepartment.Items.Add($item.Department.Trim())
    }

    foreach ($item in $FileOffice) {
        $ListOffice.Items.Add($item.Office.Trim())
    }

    foreach ($item in $FileTitle) {
        $ListTitle.Items.Add($item.Title.Trim())
    }
    
    # -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
    
    $ListAD = Get-ADObject -LDAPFilter 'objectclass=organizationalUnit' -Properties * | 
    Where-Object { $_.objectclass -in 'organizationalUnit' } | 
    Sort-Object canonicalName, DistinguishedName
    $ExtractPathName = @{}
    foreach ($ADFolder in $ListAD){
        $splitPath = $ADFolder.canonicalName -split '/' | Select-Object -Skip 1
        $OUString = $splitPath -join '/'
        $ExtractPathName[$OUString] = $ADFolder.DistinguishedName
    }
    
    $OrderedHashAD = $ExtractPathName.GetEnumerator() | Sort-Object -Property Name
    foreach($item in $OrderedHashAD) {
        $ListOU.Items.Add($item.Name)
    }

    # -------------------------------------------------- Search and select an item for description, Office, Title, Deparment and Company --------------------------------------------------
    # Search Description
    $searchItemDescription = $Actualdescription
    $indexDesciption = $ListDescription.FindStringExact($searchItemDescription)

    if ($indexDesciption -ne -1) {
        $ListDescription.SelectedIndex = $indexDesciption
    }

    # Search Office
    $searchItemOffice = $Actualoffice
    $indexOffice = $ListOffice.FindStringExact($searchItemOffice)

    if ($indexOffice -ne -1) {
        $ListOffice.SelectedIndex = $indexOffice
    }

    # Search Title
    $searchItemTitle= $Actualtitle
    $indexTitle= $ListTitle.FindStringExact($searchItemTitle)

    if ($indexTitle -ne -1) {
        $ListTitle.SelectedIndex = $indexTitle
    }

    # Search Department
    $searchItemDepartment = $Actualdepartment
    $indexDepartment = $ListDepartment.FindStringExact($searchItemDepartment)

    if ($indexDepartment -ne -1) {
        $ListDepartment.SelectedIndex = $indexDepartment
    }

    # Search Company
    $searchItemCompany = $Actualcompany
    $indexCompany = $ListCompany.FindStringExact($searchItemCompany)

    if ($indexCompany -ne -1) {
        $ListCompany.SelectedIndex = $indexCompany
    }

    # Search OU
    $searchListAD = Get-ADObject -LDAPFilter 'objectclass=organizationalUnit' -Properties canonicalName | 
    Where-Object { $_.objectclass -in 'organizationalUnit' -and $_.distinguishedName -in "$DNString"} | 
    Sort-Object canonicalName |
    Select-Object canonicalName, distinguishedName

    $searchSplitPath = $searchListAD.canonicalName -split '/' | Select-Object -Skip 1
    $searchOUString = $searchSplitPath -join '/'
    $indexOU = $ListOU.FindStringExact($searchOUString)

    if ($indexOU -ne -1) {
        $ListOU.SelectedIndex = $indexOU
    }

    #---------------------------------------------------------------------------------------------------------------------------------------------------------

    # --------------------------------------------- Displays a message in each dropdown -----------------------------------------------------------------
    $ListDescription.Add_DrawItem(
        {param($sender,$e)
        $text = "-- Seleccionar Descripción --"
        if ($e.Index -gt -1){
            $text = $sender.GetItemText($sender.Items[$e.Index])
        }
        $e.DrawBackground()
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $text, $combo.Font, `
            $e.Bounds, $e.ForeColor, [System.Windows.Forms.TextFormatFlags]::Default)
    })
    
    $ListCompany.Add_DrawItem(
        {param($sender,$e)
        $text = "-- Seleccionar Compañía --"
        if ($e.Index -gt -1){
            $text = $sender.GetItemText($sender.Items[$e.Index])
        }
        $e.DrawBackground()
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $text, $combo.Font, `
            $e.Bounds, $e.ForeColor, [System.Windows.Forms.TextFormatFlags]::Default)
    })

    $ListDepartment.Add_DrawItem(
        {param($sender,$e)
        $text = "-- Seleccionar Departamento --"
        if ($e.Index -gt -1){
            $text = $sender.GetItemText($sender.Items[$e.Index])
        }
        $e.DrawBackground()
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $text, $combo.Font, `
            $e.Bounds, $e.ForeColor, [System.Windows.Forms.TextFormatFlags]::Default)
    })

    $ListTitle.Add_DrawItem(
        {param($sender,$e)
        $text = "-- Seleccionar Título --"
        if ($e.Index -gt -1){
            $text = $sender.GetItemText($sender.Items[$e.Index])
        }
        $e.DrawBackground()
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $text, $combo.Font, `
            $e.Bounds, $e.ForeColor, [System.Windows.Forms.TextFormatFlags]::Default)
    })
      
    $ListOffice.Add_DrawItem(
        {param($sender,$e)
        $text = "-- Seleccionar Oficina --"
        if ($e.Index -gt -1){
            $text = $sender.GetItemText($sender.Items[$e.Index])
        }
        $e.DrawBackground()
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $text, $combo.Font, `
            $e.Bounds, $e.ForeColor, [System.Windows.Forms.TextFormatFlags]::Default)
    })
    
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
    # --------------------------------------------------------------------------------------------------------------------------------------------
    # Checkbox to email input
    $CBEmail.Add_CheckedChanged({
        if ($CBEmail.Checked) {
            $TBEmail.Enabled = $true
        } else {
            $TBEmail.Enabled = $false
        }
        UpdateButtonState
    })
    # ---------------------------------------------------------- Check fields ----------------------------------------------------------------------
    # If there´s any changes in fields, invokes funtion UpdateButtonState
    # Name and surnames also contain an additional funtion that allows to auto write username
	$TBNombre.Add_Leave({
        $TBNombre.Text = (Get-CapitalizedString $TBNombre.Text)     
    })

    $TBNombre.Add_TextChanged({
        UpdateUsername
        $State.Name = UpdateStateName
        UpdateButtonState
    })

    function UpdateStateName{
        $Newnombre = $TBNombre.Text.Trim()
        # Check name contains something
        if ($Actualnombre -ceq $Newnombre) {
            $SMSNombre.Text = "Igual."
            $SMSNombre.ForeColor = [System.Drawing.Color]::Red
            return $false
        } else {
            if(![string]::IsNullOrWhiteSpace($Newnombre)) {
                $SMSNombre.Text = "Válido."
                $SMSNombre.ForeColor = [System.Drawing.Color]::Green
                return $true
            } else {
                $SMSNombre.Text = "Rellene este campo."
                $SMSNombre.ForeColor = [System.Drawing.Color]::Red
                return $false
            }
        }
        
    }

    $TBApellidos.Add_Leave({
        $TBApellidos.Text = (Get-CapitalizedString $TBApellidos.Text)
        
    })

    $TBApellidos.Add_TextChanged({
        UpdateUsername
        $State.Surname = UpdateStateSurname
        UpdateButtonState
    })

    function UpdateStateSurname{
        $Newapellidos = $TBApellidos.Text.Trim()
        # Check surname contains something
        if ($Actualapellidos -ceq $Newapellidos) {
            $SMSApellidos.Text = "Igual."
            $SMSApellidos.ForeColor = [System.Drawing.Color]::Red
            return $false
        } else {
            if(![string]::IsNullOrWhiteSpace($Newapellidos)) {
                $SMSApellidos.Text = "Válido."
                $SMSApellidos.ForeColor = [System.Drawing.Color]::Green
                return $true
            } else {
                $SMSApellidos.Text = "Rellene este campo."
                $SMSApellidos.ForeColor = [System.Drawing.Color]::Red
                return $false
            }
        }
        
    }

    $TBID.Add_TextChanged({
        $TBID.Text = $TBID.Text.Trim()
        # Capitalize the last character
        if ($TBID.Text -cmatch "^\d{8}[a-z]$") {
            $TBID.Text = $TBID.Text.Substring(0, $TBID.Text.Length - 1) + $TBID.Text[-1].ToString().ToUpper()
        } elseif ($TBID.Text -cmatch "^[XYZ]\d{7}[a-z]$" -or $TBID.Text -cmatch "^[xyz]\d{7}[a-z]$" -or $TBID.Text -cmatch "^[xyz]\d{7}[A-Z]$") {
            # Both sides
            $TBID.Text = $TBID.Text.Substring(0, 1).ToUpper() + $TBID.Text.Substring(1, $TBID.Text.Length - 2) + $TBID.Text.Substring($TBID.Text.Length - 1).ToUpper()
        }
    })

    $TBID.Add_TextChanged({  
        $State.ID = UpdateStateID
        UpdateButtonState
    })

    function UpdateStateID {
        # Consults ID
        $NewID = $TBID.Text.Trim()
        $checkPatternID = checkPatternID -ID $TBID.Text.Trim()
        if($checkPatternID) {
            $checkID = validateID -ID $NewID
            
            if($checkID -ceq $true) {
                $SMSID.Text = "Válido."
                $SMSID.ForeColor = [System.Drawing.Color]::Green
                return $true
            } elseif ($Actualid -ceq $newID) {
                $SMSID.Text = "Igual"
                $SMSID.ForeColor = [System.Drawing.Color]::Red
                return $false
            } elseif ($checkID -ceq $false) {
                $SMSID.Text = "Existe."
                $SMSID.ForeColor = [System.Drawing.Color]::Red
                return $false
            }
        } elseif ($checkPatternID -eq $false ) {
            $SMSID.Text = "Inválido."
            $SMSID.ForeColor = [System.Drawing.Color]::Red
            return $false
        }  
    }

    $TBUsuario.Add_TextChanged({
        $State.Username = UpdateStateUsername
        UpdateButtonState
    })

    function UpdateStateUsername {
        $Newusuario = $TBUsuario.Text.Trim()
        # Check username 
        if(![string]::IsNullOrWhiteSpace($Newusuario)) {
			# Checks username pattern
            $checkPatternUsernam = checkPatternUsername -username $Newusuario
            if($checkPatternUsernam){
				# Returns wether username exists
                $checkUsuario = validateUsername -username ($Newusuario)
                if($Actualusuario -eq ($Newusuario)){                   
                    $SMSUsuario.Text = "Igual"
                    $SMSUsuario.ForeColor = [System.Drawing.Color]::Red
                    return $false
                } elseif($checkUsuario) {
                    $SMSUsuario.Text = "Válido"
                    $SMSUsuario.ForeColor = [System.Drawing.Color]::Green
                    return $true
                } elseif($checkUsuario -eq $false) {
                    $SMSUsuario.Text = "Existe"
                    $SMSUsuario.ForeColor = [System.Drawing.Color]::Red
                    return $false
                }
            }  else {
                $SMSUsuario.Text = "No puede haber tildes ni eñes ni cedillas ni caracteres especiales"
                $SMSUsuario.ForeColor = [System.Drawing.Color]::Red
                return $false
            }
        } else {
            $SMSUsuario.Text = "Rellene este campo."
            $SMSUsuario.ForeColor = [System.Drawing.Color]::Red
            return $false
        }
    }

    $TBEmail.Add_TextChanged({
        $State.Email = UpdateStateEmail
        UpdateButtonState
    })

    function UpdateStateEmail {
        $newEmail = $TBEmail.Text.Trim()
        # Check email pattern
        if($CBEmail.checked){
            if($Actualemail -eq $newEmail) {
                $SMSEmail.Text = "Igual"
                $SMSEmail.ForeColor =[System.Drawing.Color]::Red
                return $false
            }
            elseif (($stateEmail = validateEmail -email $newEmail) -eq $true) {
                $SMSEmail.Text = "Válido"
                $SMSEmail.ForeColor =[System.Drawing.Color]::Green
                return $true
            } else {
                $SMSEmail.Text = "Inválido"
                $SMSEmail.ForeColor =[System.Drawing.Color]::Red
                return $false
            }
        } else {
            $TBEmail.Text = $Actualemail
            $SMSEmail.Text = "Opcional"
            $SMSEmail.ForeColor =[System.Drawing.Color]::LimeGreen
            return $true
        }  
    }

    # Add event handler for selected index change in ComboBox
    $ListDescription.add_SelectedIndexChanged({
        $State.Description = UpdateStateListDescription
        UpdateButtonState
    })

    # Add event handler for selected index change in ComboBox
    $ListOffice.add_SelectedIndexChanged({
        $State.Office = UpdateStateListOffice
        UpdateButtonState
    })

    # Add event handler for selected index change in ComboBox
    $ListTitle.add_SelectedIndexChanged({
        $State.Title = UpdateStateListTitle
        UpdateButtonState
    })
    
    # Add event handler for selected index change in ComboBox
    $ListDepartment.add_SelectedIndexChanged({
        $State.Department = UpdateStateListDepartment
        UpdateButtonState
    })

    # Add event handler for selected index change in ComboBox
    $ListCompany.add_SelectedIndexChanged({
        $State.Company = UpdateStateListCompany
        UpdateButtonState
    })

    # Add event handler for selected index change in ComboBox
    $ListOU.add_SelectedIndexChanged({
        $State.OU = UpdateStateListOU
        UpdateButtonState
    })

    function UpdateButtonState{
        
        $AllStateFields = ($State.Name -or $State.Surname -or $State.ID -or $State.Username -or $State.Email `
        -or $State.Description -or $State.Office -or $State.Title `
        -or $State.Department -or $State.OU -or $State.Company)
        # Check all input states to enable button
        if($CBEmail.Checked) {
            if($AllStateFields) {
                $BotonAceptar.Enabled = $true
            } else {
                $BotonAceptar.Enabled = $false
            }
        } else {
            if($AllStateFields) {
                $BotonAceptar.Enabled = $true
            } else {
                $BotonAceptar.Enabled = $false
            }
        }
    }
    # ----------------------------------------------------------------------------------------------------------------------------------
    # Capitalizing first letter for each word
    function Get-CapitalizedString {
        param (
            [string]$inputString
        )
        if(![string]::IsNullOrWhiteSpace($inputString.Trim())){
            $words = $inputString -split '\s+'
            $capitalizedWords = foreach ($word in $words) {
                $firstLetter = $word[0].ToString().ToUpper()
                $restOfWord = $word.Substring(1).ToLower()
                $firstLetter + $restOfWord
            }
        
            $result = $capitalizedWords -join ' '
        
            return $result
        }
    }
    # Autofills username
    function UpdateUsername{
        $name = $TBNombre.Text.Trim()
        $surname = $TBApellidos.Text.Trim()
        if([string]::IsNullOrWhiteSpace($name)) {
            $firstLetterName = ""
        } else {
            $firstLetterName = $name.Substring(0, 1)
        }

        if([string]::IsNullOrWhiteSpace($surname)) {
            $firstSurname = ""
        }

        # Splits surnames into an array and selects the first one
        $firstSurname = $surname -split '\s' | Select-Object -First 1
        # Build the email using the first letter of the name and surnames
        $TBUsuario.Text = ($firstLetterName + $firstSurname).ToLower()
        
    }

    # ----------------------------------- check dropdowns ----------------------------------------
    function UpdateStateListDescription{
        $Newdescripcion = $ListDescription.SelectedItem
        if($Newdescripcion -eq $Actualdescription) {
            $SMSDescription.Text = "Igual."
            $SMSDescription.ForeColor = [System.Drawing.Color]::Red
            return $false
        } elseif ($ListDescription.SelectedItem -ne $null) {
            $SMSDescription.Text = "Válido"
            $SMSDescription.ForeColor = [System.Drawing.Color]::Green
            return $true
        } else {
            $SMSDescription.Text = "Obligatorio."
            $SMSDescription.ForeColor = [System.Drawing.Color]::Red
            return $false
        }
    }
    function UpdateStateListOffice {
        $Newoffice = $ListOffice.SelectedItem
        if($Newoffice -eq $Actualoffice) {
            $SMSOffice.Text = "Igual."
            $SMSOffice.ForeColor = [System.Drawing.Color]::Red
            return $false
        } elseif($ListOffice.SelectedItem -ne $null) {
            $SMSOffice.Text = "Válido"
            $SMSOffice.ForeColor = [System.Drawing.Color]::Green
            return $true
        } else {
            $SMSOffice.Text = "Obligatorio."
            $SMSOffice.ForeColor = [System.Drawing.Color]::Red
            return $false
        }
        
    }

    function UpdateStateListTitle {
        $Newtitle = $ListTitle.SelectedItem        
        if($Newtitle -eq $Actualtitle) {
            $SMSTitle.Text = "Igual."
            $SMSTitle.ForeColor = [System.Drawing.Color]::Red
            return $false
        } elseif ($ListTitle.SelectedItem -ne $null) {
            $SMSTitle.Text = "Válido"
            $SMSTitle.ForeColor = [System.Drawing.Color]::Green
            return $true
        } else {
            $SMSTitle.Text = "Obligatorio."
            $SMSTitle.ForeColor = [System.Drawing.Color]::Red
            return $false
        }
        
    }

    function UpdateStateListDepartment {
        $Newdept = $ListDepartment.SelectedItem
        if($Newdept -eq $Actualdepartment) {
            $SMSDepartment.Text = "Igual."
            $SMSDepartment.ForeColor = [System.Drawing.Color]::Red
            return $false
        } elseif ($ListDepartment.SelectedItem -ne $null) {
            $SMSDepartment.Text = "Válido"
            $SMSDepartment.ForeColor = [System.Drawing.Color]::Green
            return $true
        } else {
            $SMSDepartment.Text = "Obligatorio."
            $SMSDepartment.ForeColor = [System.Drawing.Color]::Red
            return $false
        }
    }

    function UpdateStateListCompany {
        $Newcomp = $ListCompany.SelectedItem
        if($Newcomp -eq $Actualcompany) {
            $SMSCompany.Text = "Igual."
            $SMSCompany.ForeColor = [System.Drawing.Color]::Red
            return $false
        } elseif ($ListCompany.SelectedItem -ne $null) {
            $SMSCompany.Text = "Válido"
            $SMSCompany.ForeColor = [System.Drawing.Color]::Green
            return $true
        } else {
            $SMSCompany.Text = "Obligatorio."
            $SMSCompany.ForeColor = [System.Drawing.Color]::Red
            return $false
        }
        
    }

    function UpdateStateListOU {
        $selectedOU = $ListOU.SelectedItem
        $NewDN = $ExtractPathName[$selectedOU]
        if($NewDN -eq $DNString) {
            $SMSOU.Text = "Igual."
            $SMSOU.ForeColor = [System.Drawing.Color]::Red
            return $false
        } elseif ($ListOU.SelectedItem -ne $null) {
            $SMSOU.Text = "Válido"
            $SMSOU.ForeColor = [System.Drawing.Color]::Green
            return $true
        } else {
            $SMSOU.Text = "Obligatorio."
            $SMSOU.ForeColor = [System.Drawing.Color]::Red
            return $false
        }
        
    }

    # ----------------------------------------------------------------------------------------------------
 
    # ------------------------------------------------------- Modify user's data Aceptar----------------------------------------------------
    $BotonAceptar.Add_Click({
        
        $Newnombre = $TBNombre.Text.Trim()
        $Newapellidos = $TBApellidos.Text.Trim()
        $NewID = $TBID.Text.Trim()
        $Newusuario = $TBUsuario.Text.Trim()
        $Newemail = $TBEmail.Text.Trim()
        if($CBEmail.Checked -eq $false) {
            $Newemail = $null
        }
        #$Newpw = ConvertTo-SecureString -String $TBPassword.Text -AsPlainText -Force
        $Newdescripcion = $ListDescription.SelectedItem
        $Newoficina = $ListOffice.SelectedItem
        $Newtitulo = $ListTitle.SelectedItem
        $Newdept = $ListDepartment.SelectedItem
        $Newcomp = $ListCompany.SelectedItem
	    $selectedDN = $ListOU.SelectedItem
        $idDN = $ExtractPathName[$selectedDN]
        
		# List all changes and shows on a pop up window
        if($CBEmail.Checked) {
            #Set of variables of array type
            $stringArr = @("Nombre: ","Apellidos: ","DNI/NIE: ","Usuario: ","Correo externo: ", "Descripción: ","Oficina: ","Título: ","Departamento: ","Compañía: ","OU: ")
            $ActualValues = @($Actualnombre,$Actualapellidos,$ActualID,$Actualusuario,$Actualemail,$Actualdescription,$Actualoffice,$Actualtitle,$Actualdepartment,$Actualcompany,$searchOUString)
            $NewValues = @($Newnombre,$Newapellidos,$NewID,($Newusuario+$DomainName),$Newemail,$Newdescripcion,$Newoficina,$Newtitulo,$Newdept,$Newcomp,$selectedDN)
            
        } else {
            #Set of variables of array type
            $stringArr = @("Nombre: ","Apellidos: ","DNI/NIE: ","Usuario: ","Correo externo: ", "Descripción: ","Oficina: ","Título: ","Departamento: ","Compañía: ","OU: ")
            $ActualValues = @($Actualnombre,$Actualapellidos,$ActualID,$Actualusuario,$Actualemail,$Actualdescription,$Actualoffice,$Actualtitle,$Actualdepartment,$Actualcompany,$searchOUString)
            $NewValues = @($Newnombre,$Newapellidos,$NewID,($Newusuario+$DomainName),$Newemail,$Newdescripcion,$Newoficina,$Newtitulo,$Newdept,$Newcomp,$selectedDN)
        }
        $changes = ""        
        $checkDifference = $false

        #Checks if there are any changes between old and new values
        for($i = 0; $i -lt $ActualValues.Length; $i++) {
            $Actualelement = $($ActualValues[$i])
            $Newelement = $($NewValues[$i])

            if(-not ($Actualelement -ceq $Newelement)) {
                $checkDifference = $checkDifference -or $true
                $changes += "$($stringArr[$i])$Actualelement -> $Newelement (Modificar)`n"
            } 
            #else {
                #$changes += "$($stringArr[$i])$Actualelement (Igual)`n"

            #}
        }
        

        # Catches any changes
        if($checkDifference -eq $true) {
            #Warning Pop-up window. Needs user´s confirmation in order apply following user´s changes
            $ButtonType = [System.Windows.MessageBoxButton]::OkCancel
            $MessageIcon = [System.Windows.MessageBoxImage]::Warning
            $MessageBody = "¿Está seguro de que desea cambiar los siguientes datos del usuario? `n$changes"
            $MessageTitle = "Confirmación de cambios"
            $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
            
            # User presses Ok button
            if($Result -ceq "Ok") {
                try {
                    # Checks which ones are needed to modify
					if($State.Name -eq $true -or $stateApellidos -eq $true) {
						Set-ADUser -Identity $identity -givenName $Newnombre -Surname $Newapellidos -DisplayName ($Newnombre + " " + $Newapellidos)
                        Rename-ADObject -Identity $identity -NewName ($Newnombre + " " + $Newapellidos)
					}
                    if($State.Surname -eq $true){
                        Set-ADUser -Identity $identity -EmployeeID $NewID
                    }
                    if($State.Username -eq $true){
                        Set-ADUser -Identity $identity -SamAccountName $Newusuario -UserPrincipalName ($Newusuario+$DomainName)
                    }
                    if($CBEmail.checked -and $State.Email -eq $true){
                        Set-ADUser -Identity $identity -EmailAddress $Newemail
                    } else {
                        Set-ADUser -Identity $identity -EmailAddress $Newemail
                    }
                    if($State.Description -eq $true){
                        Set-ADUser -Identity $identity -Description $Newdescripcion
                    }
                    if($State.Office -eq $true){
                        Set-ADUser -Identity $identity -Office $Newoficina
                    }
                    if($State.Title -eq $true){
                        Set-ADUser -Identity $identity -Title $Newtitulo
                    }
                    if($State.Department -eq $true){
                        Set-ADUser -Identity $identity -Department $Newdept
                    }
                    if($State.Company -eq $true){
                        Set-ADUser -Identity $identity -Company $Newcomp
                    }
                    if($state.OU -eq $true){
                        Move-ADObject -Identity $identity -TargetPath $idDN
                    }

                    #Warning Pop-up window. Needs user´s confirmation in order apply following user´s changes
                    $ButtonType = [System.Windows.MessageBoxButton]::Ok
                    $MessageIcon = [System.Windows.MessageBoxImage]::Information
                    $MessageBody = "Datos actualizados."
                    $MessageTitle = "Información"
                    [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
					(viewlistUser -keywords $TextoBuscador.Text -activateSearch $true)
                    $Form.Close()

                }
                catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
                    $message_Error += "Error: The specified identity already exists.`n"
                }
                catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                    $message_Error += "Error: The specified identity was not found.`n"
                }
                catch [Microsoft.ActiveDirectory.Management.ADInvalidOperationException] {
                    $message_Error += "Error: Invalid operation. Check the provided parameters.`n"
                }
                catch [Microsoft.ActiveDirectory.Management.ADException] {
                    $message_Error += "$_`n"
                }

                # Any errors will be shown for ID and catch event 
                if($message_Error -ne $null -and $message_Error -ne "") { 
                    #Warning Pop-up window. Needs user´s confirmation in order apply following user´s changes
                    $ButtonType = [System.Windows.MessageBoxButton]::Ok
                    $MessageIcon = [System.Windows.MessageBoxImage]::Error
                    $MessageBody = "Se ha producido el siguiente error: `n$message_Error `nNo se va realizar ninguna modificación."
                    $MessageTitle = "Campos no válidos"
                    [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
                    $WindowState.IsOpen = $false
                    $Form.Close()
                }

            } else {
                #Warning Pop-up window. Needs user´s confirmation in order apply following user´s changes
                $ButtonType = [System.Windows.MessageBoxButton]::Ok
                $MessageIcon = [System.Windows.MessageBoxImage]::Information
                $MessageBody = "Modifiación anulada."
                $MessageTitle = "Operación cancelada"
                [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
                $WindowState.IsOpen = $false
                $Form.Close()
            }
        }

     })
    # -------------------------------------------------------------------------------------------------------------------------------------------------


    [void]$Form.ShowDialog()
    # If the window is closed, reopen it
    if (-not $WindowState.IsOpen) {
       EditUser -identity $identity -identityDN $identityDN -WindowState $WindowState
    }    
    
}