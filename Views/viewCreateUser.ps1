# ---------------------------------------- Create user view funtion--------------------------------------------------
function CreateUser {
    $DropdownHeight = 500
    # Creat user View
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $Form                            = New-Object system.Windows.Forms.Form
    $Form.ClientSize                 = New-Object System.Drawing.Point(700,700)
    $Form.text                       = "Crear Usuario"
    $Form.TopMost                    = $false
    $Form.FormBorderStyle            = "FixedDialog"
    $Form.MaximizeBox                = $false

    # --------------------------------------------- List of elements in the form --------------------------------------------------------------
    # Nombre
    $TBNombre                        = New-Object system.Windows.Forms.TextBox
    $TBNombre.multiline              = $false
    $TBNombre.width                  = 200
    $TBNombre.height                 = 20
    $TBNombre.location               = New-Object System.Drawing.Point(135,20)
    $TBNombre.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

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

    # DNI
    $TBID                        = New-Object system.Windows.Forms.TextBox
    $TBID.multiline              = $false
    $TBID.width                  = 150
    $TBID.height                 = 20
    $TBID.location               = New-Object System.Drawing.Point(135,120)
    $TBID.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $SMSID                       = New-Object system.Windows.Forms.Label
    $SMSID.AutoSize              = $true
    $SMSID.width                 = 25
    $SMSID.height                = 10
    $SMSID.location              = New-Object System.Drawing.Point(135,145)
    $SMSID.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

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
    $LblDomain.height                = 15
    $LblDomain.location              = New-Object System.Drawing.Point(350,170)
    $LblDomain.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $CBCreateEmail                          = New-Object System.Windows.Forms.CheckBox
    $CBCreateEmail.Text                     = "Crear cuenta de correo"
    $CBCreateEmail.width                    = 170
    $CBCreateEmail.location                 = New-Object System.Drawing.Point(480,170)
    $CBCreateEmail.Checked                  = $false
    $CBCreateEmail.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Password
    $TBPassword                        = New-Object system.Windows.Forms.MaskedTextBox
    $TBPassword.PasswordChar             = '*'
    $TBPassword.multiline              = $false
    $TBPassword.width                  = 200
    $TBPassword.height                 = 20
    $TBPassword.location               = New-Object System.Drawing.Point(135,220)
    $TBPassword.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    $SMSPassword                       = New-Object system.Windows.Forms.Label
    $SMSPassword.AutoSize              = $true
    $SMSPassword.height                = 10
    $SMSPassword.location              = New-Object System.Drawing.Point(135,245)
    $SMSPassword.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblPassword                       = New-Object system.Windows.Forms.Label
    $LblPassword.Text                  = "Clave:"
    $LblPassword.AutoSize              = $true
    $LblPassword.width                 = 25
    $LblPassword.height                = 10
    $LblPassword.location              = New-Object System.Drawing.Point(20,220)
    $LblPassword.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    # Create checkbox to show password value
    $CBShowPassword                         = New-Object System.Windows.Forms.CheckBox
    $CBShowPassword.Text                    = "Mostrar clave"
    $CBShowPassword.location                = New-Object System.Drawing.Point(350,220)
    $CBShowPassword.width                   = 110
    $CBShowPassword.Checked                 = $false
    $CBShowPassword.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $CBChangeNextLogon                          = New-Object System.Windows.Forms.CheckBox
    $CBChangeNextLogon.Text                     = "Cambiar clave en el siguente inicio sesión"
    $CBChangeNextLogon.location                 = New-Object System.Drawing.Point(480,215)
    $CBChangeNextLogon.width                    = 160
    $CBChangeNextLogon.height                   = 35
    $CBChangeNextLogon.Checked                  = $false
    $CBChangeNextLogon.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    # External Email
    $TBEmail                        = New-Object system.Windows.Forms.TextBox
    $TBEmail.multiline              = $false
    $TBEmail.width                  = 250
    $TBEmail.height                 = 20
    $TBEmail.location               = New-Object System.Drawing.Point(135,270)
    $TBEmail.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBEmail.Enabled                = $false
    
    $SMSEmail                       = New-Object system.Windows.Forms.Label
    $SMSEmail.AutoSize              = $true
    $SMSEmail.height                = 10
    $SMSEmail.location              = New-Object System.Drawing.Point(135,295)
    $SMSEmail.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblEmail                       = New-Object system.Windows.Forms.Label
    $LblEmail.Text                  = "Correo externo:"
    $LblEmail.AutoSize              = $true
    $LblEmail.width                 = 25
    $LblEmail.height                = 10
    $LblEmail.location              = New-Object System.Drawing.Point(20,270)
    $LblEmail.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Create checkbox to toggle Email input visibility
    $CBEmail                            = New-Object System.Windows.Forms.CheckBox
    $CBEmail.Text                       = "Añadir correo"
    $CBEmail.location                   = New-Object System.Drawing.Point(400,270)
    $CBEmail.width                      = 110
    $CBEmail.Checked                    = $false
    $CBEmail.Font                       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Description
    $ListDescription                        = New-Object system.Windows.Forms.ComboBox
    $ListDescription.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListDescription.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListDescription.autosize               = $true
    $ListDescription.Size                   = New-Object System.Drawing.Size(400, 20)
    $ListDescription.location               = New-Object System.Drawing.Point(135,320)
    $ListDescription.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ListDescription.DropDownHeight         = $DropdownHeight

    $SMSDescription                       = New-Object system.Windows.Forms.Label
    $SMSDescription.AutoSize              = $true
    $SMSDescription.height                = 10
    $SMSDescription.location              = New-Object System.Drawing.Point(135,345)
    $SMSDescription.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblDescription                      = New-Object system.Windows.Forms.Label
    $LblDescription.text                  = "Descripción:"
    $LblDescription.AutoSize              = $true
    $LblDescription.width                 = 25
    $LblDescription.height                = 10
    $LblDescription.location              = New-Object System.Drawing.Point(20,320)
    $LblDescription.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Office
    $ListOffice                        = New-Object system.Windows.Forms.ComboBox
    $ListOffice.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListOffice.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListOffice.autosize               = $true
    $ListOffice.Size                   = New-Object System.Drawing.Size(400, 20)
    $ListOffice.location               = New-Object System.Drawing.Point(135,370)
    $ListOffice.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ListOffice.DropDownHeight          = $DropdownHeight

    $SMSOffice                       = New-Object system.Windows.Forms.Label
    $SMSOffice.AutoSize              = $true
    $SMSOffice.height                = 10
    $SMSOffice.location              = New-Object System.Drawing.Point(135,395)
    $SMSOffice.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblOffice                       = New-Object system.Windows.Forms.Label
    $LblOffice.text                  = "Oficina:"
    $LblOffice.AutoSize              = $true
    $LblOffice.width                 = 25
    $LblOffice.height                = 10
    $LblOffice.location              = New-Object System.Drawing.Point(20,370)
    $LblOffice.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Title
    $ListTitle                        = New-Object system.Windows.Forms.ComboBox
    $ListTitle.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListTitle.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListTitle.autosize               = $true
    $ListTitle.Size                   = New-Object System.Drawing.Size(400, 20)
    $ListTitle.location               = New-Object System.Drawing.Point(135,420)
    $ListTitle.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ListTitle.DropDownHeight           = $DropdownHeight

    $SMSTitle                       = New-Object system.Windows.Forms.Label
    $SMSTitle.AutoSize              = $true
    $SMSTitle.height                = 10
    $SMSTitle.location              = New-Object System.Drawing.Point(135,445)
    $SMSTitle.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblTitle                       = New-Object system.Windows.Forms.Label
    $LblTitle.text                  = "Título:"
    $LblTitle.AutoSize              = $true
    $LblTitle.width                 = 25
    $LblTitle.height                = 10
    $LblTitle.location              = New-Object System.Drawing.Point(20,420)
    $LblTitle.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Department
    $ListDepartment                        = New-Object system.Windows.Forms.ComboBox
    $ListDepartment.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListDepartment.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListDepartment.autosize               = $true
    $ListDepartment.Size                   = New-Object System.Drawing.Size(400, 20)
    $ListDepartment.location               = New-Object System.Drawing.Point(135,470)
    $ListDepartment.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ListDepartment.DropDownHeight          = $DropdownHeight

    $SMSDepartment                       = New-Object system.Windows.Forms.Label
    $SMSDepartment.AutoSize              = $true
    $SMSDepartment.height                = 10
    $SMSDepartment.location              = New-Object System.Drawing.Point(135,495)
    $SMSDepartment.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblDepartment                       = New-Object system.Windows.Forms.Label
    $LblDepartment.text                  = "Departamento:"
    $LblDepartment.AutoSize              = $true
    $LblDepartment.width                 = 25
    $LblDepartment.height                = 10
    $LblDepartment.location              = New-Object System.Drawing.Point(20,470)
    $LblDepartment.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Company
    $ListCompany                        = New-Object system.Windows.Forms.ComboBox
    $ListCompany.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListCompany.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListCompany.Size                   = New-Object System.Drawing.Size(400, 20)
    $ListCompany.location               = New-Object System.Drawing.Point(135,520)
    $ListCompany.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ListCompany.DropDownHeight         = $DropdownHeight

    $SMSCompany                       = New-Object system.Windows.Forms.Label
    $SMSCompany.AutoSize              = $true
    $SMSCompany.height                = 10
    $SMSCompany.location              = New-Object System.Drawing.Point(135,545)
    $SMSCompany.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LblCompany                       = New-Object system.Windows.Forms.Label
    $LblCompany.text                  = "Compañía:"
    $LblCompany.AutoSize              = $true
    $LblCompany.width                 = 25
    $LblCompany.height                = 10
    $LblCompany.location              = New-Object System.Drawing.Point(20,520)
    $LblCompany.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # OU list
    $LblOU                       = New-Object system.Windows.Forms.Label
    $LblOU.text                  = "OU:"
    $LblOU.AutoSize              = $true
    $LblOU.width                 = 25
    $LblOU.height                = 10
    $LblOU.location              = New-Object System.Drawing.Point(20,570)
    $LblOU.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $ListOU                        = New-Object system.Windows.Forms.ComboBox
    $ListOU.DropDownStyle          = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ListOU.DrawMode               = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
    $ListOU.Size                   = New-Object System.Drawing.Size(650, 20)
    $ListOU.location               = New-Object System.Drawing.Point(20,590)
    $ListOU.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',9)
    $ListOU.DropDownHeight         = $DropdownHeight
    
    $SMSOU                       = New-Object system.Windows.Forms.Label
    $SMSOU.AutoSize              = $true
    $SMSOU.height                = 10
    $SMSOU.location              = New-Object System.Drawing.Point(20,615)
    $SMSOU.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Aceptar
    $BotonAceptar                    = New-Object system.Windows.Forms.Button
    $BotonAceptar.text               = "Añadir"
    $BotonAceptar.width              = 60
    $BotonAceptar.height             = 30
    $BotonAceptar.location           = New-Object System.Drawing.Point(300,650)
    $BotonAceptar.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $BotonAceptar.Enabled            = $false

    # Create a ToolTips
    $toolTipID = New-Object Windows.Forms.ToolTip
    $toolTipID.SetToolTip($TBID, "DNI: 8 números y una letra en mayúscula `nNIE: Letra X, Y o Z, 7 números y una letra en mayúscula")

    $toolTipPassword = New-Object Windows.Forms.ToolTip
    $toolTipPassword.SetToolTip($TBPassword, "Debe contener al menos 12 caracteres y al menos tres de estas opciones:" +
                        "`n-Al menos una letra mayúscula" + "`n-Al menos una letra minúscula" + "`n-Al menos un número" +
                        "`n-Al menos un carácter especial"
                        )

    # ----------------------------------------------------------------- Add buttons in form----------------------------------------------------------------------
    $Form.controls.AddRange(@($TBNombre,$SMSNombre,$LblNombre,$TBApellidos,$SMSApellidos,$LblApellidos,$TBID,$SMSID,$LblID,$LblUsuario,$TBUsuario,$SMSUsuario,$CBCreateEmail, `
    $LblDomain,$LblPassword,$TBPassword,$SMSPassword,$CBShowPassword,$CBChangeNextLogon,$LblEmail,$TBEmail,$CBEmail,$SMSEmail,$LblDescription,$ListDescription,$SMSDescription,$LblOffice,$ListOffice,$SMSOffice,$LblTitle,$ListTitle, ` 
    $SMSTitle,$LblDepartment,$ListDepartment,$SMSDepartment,$LblCompany,$ListCompany,$SMSCompany,$LblOU,$ListOU,$SMSOU,$BotonAceptar))

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
    # ---------------------------------------------------------------------------------------------------------------------------------------------------
    # Search OU objects and add to dropdownlist
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
    # ------------------------------------------------------ Displays a message in each dropdown ---------------------------------------------------------
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
    
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------------------

    # Checkbox to show password
    $CBShowPassword.Add_CheckedChanged({
        if ($CBShowPassword.Checked) {
            $TBPassword.PasswordChar = 0
        } else {
            $TBPassword.PasswordChar = '*'
        }
    })

    # Checkbox to email input
    $CBEmail.Add_CheckedChanged({
        if ($CBEmail.Checked) {
            $TBEmail.Enabled = $true
        } else {
            $TBEmail.Enabled = $false
        }
        UpdateButtonState
    })

    # ------------------------------------------------------------ Check fields ------------------------------------------------------------------------
    
    # If there are any changes in fields, invokes funtion UpdateButtonState
    # Name and surnames also contain an additional function that allows to auto write username
    # Define a custom object to store state information
    $State = [PSCustomObject]@{
        Name = $false
        Surname = $false
        ID = $false
        Username = $false
        Password = $false
        Email = $false
        Description = $false
        Office = $false
        Title = $false
        Department = $false
        Company = $false
        OU = $false
    }
    
    $TBNombre.Add_Leave({
        $TBNombre.Text = (Get-CapitalizedString $TBNombre.Text)
    })

    $TBNombre.Add_TextChanged({
        UpdateUsername
        $State.Name = UpdateStateName
        UpdateButtonState
    })

    function UpdateStateName{
        $name = $TBNombre.Text.Trim()
        # Check name contains something
        if(![string]::IsNullOrWhiteSpace($name)) {
            $SMSNombre.Text = "Válido."
            $SMSNombre.ForeColor = [System.Drawing.Color]::Green
            return $true
        } else {
            $SMSNombre.Text = "Obligatorio."
            $SMSNombre.ForeColor = [System.Drawing.Color]::Red
            return $false
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
        # Check surname contains something
        if(![string]::IsNullOrWhiteSpace($TBApellidos.Text.Trim())) {
            $SMSApellidos.Text = "Válido."
            $SMSApellidos.ForeColor = [System.Drawing.Color]::Green
            return $true
        } else {
            $SMSApellidos.Text = "Obligatorio."
            $SMSApellidos.ForeColor = [System.Drawing.Color]::Red
            return $false
        }
        
    }
    $TBID.Add_TextChanged({
        $ID = $TBID.Text.Trim()
        # Capitalize the last character
        if ($ID -cmatch "^\d{8}[a-z]$") {
            $TBID.Text = $ID.Substring(0, $ID.Length - 1) + $ID[-1].ToString().ToUpper()
        } elseif ($ID -cmatch "^[XYZ]\d{7}[a-z]$" -or $ID -cmatch "^[xyz]\d{7}[a-z]$" -or $ID -cmatch "^[xyz]\d{7}[A-Z]$") {
            # Both sides
            $TBID.Text = $ID.Substring(0, 1).ToUpper() + $ID.Substring(1, $ID.Length - 2) + $ID.Substring($ID.Length - 1).ToUpper()
        }
    })

    $TBID.Add_TextChanged({  
        $State.ID = UpdateStateID
        UpdateButtonState
    })

    function UpdateStateID {
        # Consults ID
        $checkPatternID = checkPatternID -ID $TBID.Text.Trim()
        if($checkPatternID) {
            
            $checkID = validateID -ID $TBID.Text.Trim()
            
            if($checkID -eq $true) {
                $SMSID.Text = "Válido."
                $SMSID.ForeColor = [System.Drawing.Color]::Green
                return $true
            } elseif ($checkID -eq $false){
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
        $Username = $TBUsuario.Text.Trim()
        # Check username 
        if(![string]::IsNullOrWhiteSpace($Username)) {
            # Checks username pattern
            $checkPatternUsernam = checkPatternUsername -username $Username
            if($checkPatternUsernam){
                # Returns wether username exists
                $checkUsuario = validateUsername -username $Username
                if($checkUsuario) {
                    $SMSUsuario.Text = "Válido"
                    $SMSUsuario.ForeColor = [System.Drawing.Color]::Green
                    return $true
                } else {
                    $SMSUsuario.Text = "Existe"
                    $SMSUsuario.ForeColor = [System.Drawing.Color]::Red
                    return $false
                }
            } else {
                $SMSUsuario.Text = "No puede haber tildes ni eñes ni cedillas ni caracteres especiales"
                $SMSUsuario.ForeColor = [System.Drawing.Color]::Red
                return $false
            }
        } else {
            $SMSUsuario.Text = "Obligatorio."
            $SMSUsuario.ForeColor = [System.Drawing.Color]::Red
            return $false
        }
    }


    $TBPassword.Add_TextChanged({
        UpdateStatePassword
        UpdateButtonState
    })

    function UpdateStatePassword {
        # Check password pattern and validate
        if (($State.Password  = checkValidPassword) -eq $true) {
            $SMSPassword.Text = "Válido"
            $SMSPassword.ForeColor = [System.Drawing.Color]::Green
        } else {
            $SMSPassword.Text = "Inválido"
            $SMSPassword.ForeColor = [System.Drawing.Color]::Red
        }
        
    }

    $TBEmail.Add_TextChanged({
        UpdateStateEmail
        UpdateButtonState
    })

    function UpdateStateEmail {
        $email = $TBEmail.Text.Trim()
        # Check email pattern
        if($CBEmail.checked){

            if(($State.Email = validateEmail -email $email) -eq $true) {
                $SMSEmail.Text = "Válido"
                $SMSEmail.ForeColor =[System.Drawing.Color]::Green
            } else {
                $SMSEmail.Text = "Inválido"
                $SMSEmail.ForeColor =[System.Drawing.Color]::Red
            }
        } else {
            $SMSEmail.Text = ""
        }        
    }

    # Add event handler for selected index change in ComboBox
    $ListDescription.add_SelectedIndexChanged({
        UpdateStateList
        UpdateButtonState
    })

    # Add event handler for selected index change in ComboBox
    $ListOffice.add_SelectedIndexChanged({
        UpdateStateList
        UpdateButtonState
    })

    # Add event handler for selected index change in ComboBox
    $ListTitle.add_SelectedIndexChanged({
        UpdateStateList
        UpdateButtonState
    })
    
    # Add event handler for selected index change in ComboBox
    $ListDepartment.add_SelectedIndexChanged({
        UpdateStateList
        UpdateButtonState
    })

    # Add event handler for selected index change in ComboBox
    $ListCompany.add_SelectedIndexChanged({
        UpdateStateList
        UpdateButtonState
    })
    # Add event handler for selected index change in ComboBox
    $ListOU.add_SelectedIndexChanged({
        UpdateStateList
        UpdateButtonState
    })

    function UpdateButtonState{
        $AllStateFields = ($State.Name -and $State.Surname -and $State.ID -and $State.Username -and $State.Password `
            -and $State.Description -and $State.Office -and $State.Title `
            -and $State.Department -and $State.OU -and $State.Company)
        
        if($CBEmail.Checked) {
            if($AllStateFields -and $State.Email) {
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

    # ------------------------------------------------------------------------------------------------------------------------------------------------------
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
        $Name = $TBNombre.Text.Trim()
        $Surname = $TBApellidos.Text.Trim()
        if([string]::IsNullOrWhiteSpace($Name)) {
            $firstLetterName = ""
        } else {
            $firstLetterName = $Name.Substring(0, 1)
        }

        if([string]::IsNullOrWhiteSpace($Surname)) {
            $firstSurname = ""
        }

        # Splits space in surnames into an array and selects the first one
        $firstSurname = $Surname -split '\s' | Select-Object -First 1
        # Build the email using the first letter of the name and surnames
        $TBUsuario.Text = ($firstLetterName + $firstSurname).ToLower()
        
    }

    # Password Validation
    function checkValidPassword{
        
        
        if(![string]::IsNullOrWhiteSpace($TBPassword.Text.Trim())) {
            $Password = ConvertTo-SecureString $TBPassword.Text.Trim() -AsPlainText -Force
            #Validate password pattern
            $checkPW = validatePassword -password $Password

            if($checkPW) {
                return $true
            }

            return $false
        }
            
    }
    
    # ------------------------------------ Update button state ------------------------------------------------------
    function UpdateStateList{        
        # ----------------------------------- check dropdowns ----------------------------------------
        if($ListDescription.SelectedItem -ne $null) {
            $State.Description = $true
            $SMSDescription.Text = "Válido"
            $SMSDescription.ForeColor = [System.Drawing.Color]::Green
        } else {
            $State.Description = $false
            $SMSDescription.Text = "Obligatorio."
            $SMSDescription.ForeColor = [System.Drawing.Color]::Red
        }

       if($ListOffice.SelectedItem -ne $null) {
            $State.Office = $true
            $SMSOffice.Text = "Válido"
            $SMSOffice.ForeColor = [System.Drawing.Color]::Green
        } else {
            $State.Office = $false
            $SMSOffice.Text = "Obligatorio."
            $SMSOffice.ForeColor = [System.Drawing.Color]::Red
        }

        if($ListTitle.SelectedItem -ne $null) {
            $State.Title = $true
            $SMSTitle.Text = "Válido"
            $SMSTitle.ForeColor = [System.Drawing.Color]::Green
        } else {
            $State.Title = $false
            $SMSTitle.Text = "Obligatorio."
            $SMSTitle.ForeColor = [System.Drawing.Color]::Red
        }
        
        if($ListDepartment.SelectedItem -ne $null) {
            $State.Department = $true
            $SMSDepartment.Text = "Válido"
            $SMSDepartment.ForeColor = [System.Drawing.Color]::Green
        } else {
            $State.Department = $false
            $SMSDepartment.Text = "Obligatorio."
            $SMSDepartment.ForeColor = [System.Drawing.Color]::Red
        }

        if($ListCompany.SelectedItem -ne $null) {
            $State.Company = $true
            $SMSCompany.Text = "Válido"
            $SMSCompany.ForeColor = [System.Drawing.Color]::Green
        } else {
            $State.Company = $false
            $SMSCompany.Text = "Obligatorio."
            $SMSCompany.ForeColor = [System.Drawing.Color]::Red
        }

        if($ListOU.SelectedItem -ne $null) {
            $State.OU = $true
            $SMSOU.Text = "Válido"
            $SMSOU.ForeColor = [System.Drawing.Color]::Green
        } else {
            $State.OU = $false
            $SMSOU.Text = "Obligatorio."
            $SMSOU.ForeColor = [System.Drawing.Color]::Red
        }
    }
    
    # -----------------------------------------------------------------------------------------------------------------------------------------------------------

    # ------------------------------------------------------------ Crear usuario Boton Aceptar--------------------------------------------------------------
    $BotonAceptar.Add_Click({
        
        # Variables
        $nombre = $TBNombre.Text.Trim()
        $apellidos = $TBApellidos.Text.Trim()
        $id = $TBID.Text.Trim()
        $username = $TBUsuario.text.Trim()
        $companyEmail = ($TBUsuario.text.Trim() + $domainName)
        $pw = ConvertTo-SecureString -String $TBPassword.Text -AsPlainText -Force
        $descripcion = $ListDescription.SelectedItem
        $email = $TBEmail.Text.Trim()
        $oficina = $ListOffice.SelectedItem
        $titulo = $ListTitle.SelectedItem
        $dept = $ListDepartment.SelectedItem
        $comp = $ListCompany.SelectedItem
        $selectedOU = $ListOU.SelectedItem
        $idDN = $ExtractPathName[$selectedOU]
                
        # Check if checkbox email is activated
        # In this section will print all the input values to display on a popup window after button is pressed
        if($CBEmail.Checked) {
            $listValues = @("Nombre: $nombre","Apellidos: $apellidos","DNI: $id","Usuario: $companyEmail","Correo externo: $email", "Descripción: $descripcion",
                            "Oficina: $oficina","Título: $titulo","Departamento: $dept","Compañia: $comp")
            $values = ""

            for($i = 0; $i -lt $listValues.Length; $i++) {
                $values += "$($listValues[$i])`n"
            }

        } else {
            $listValues = @("Nombre: $nombre","Apellidos: $apellidos","DNI: $id","Usuario: $companyEmail","Descripción: $descripcion",
                            "Oficina: $oficina","Título: $titulo","Departamento: $dept","Compañia: $comp")
            $values = ""

            for($i = 0; $i -lt $listValues.Length; $i++) {
                $values += "$($listValues[$i])`n"
            }
        }

        $ButtonType = [System.Windows.MessageBoxButton]::OkCancel
        $MessageIcon = [System.Windows.MessageBoxImage]::Warning
        $MessageBody = "¿Estás seguro de que quieres añadir este usuario con los siguientes datos? `n$values"
        $MessageTitle = "Confirmación"
        $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
        
        # Confirmaiton
        if($Result -eq "Ok") {
            
            $message_Error = ""
            # Process of filling user's data and create
            try{
                if($CBEmail.Checked) {
                    New-ADUser -Name ($nombre + " " + $apellidos) –SamAccountName $username –givenName $nombre –Surname $apellidos -DisplayName ($nombre + " " + $apellidos) -EmployeeID $id `
                    -UserPrincipalName $companyEmail -AccountPassword $pw -EmailAddress $email -Description $descripcion -Office $oficina -Title $titulo `
                    -department $dept -Company $comp -ScriptPath $ScriptPath -path $idDN -Enabled $true
                } else {
                    New-ADUser -Name ($nombre + " " + $apellidos) –SamAccountName $username –givenName $nombre –Surname $apellidos -DisplayName ($nombre + " " + $apellidos) -EmployeeID $id `
                    -UserPrincipalName $companyEmail -AccountPassword $pw -Description $descripcion -Office $oficina -Title $titulo `
                    -department $dept -Company $comp -ScriptPath $ScriptPath -path $idDN -Enabled $true
                }
                
                # After creattion, search user
                $userObject = Get-ADUser -Identity $username
                
                # Create user's email asociated with company
                if($CBCreateEmail.checked) {
                    Enable-RemoteMailbox -Identity $userObject -PrimarySmtpAddress $companyEmail -RemoteRoutingAddress $companyEmail -alias $username
                }
                
                # Change user's password in the next logon
                if($CBChangeNextLogon.Checked){
                    Set-ADUser -Identity $userObject -ChangePasswordAtLogon $true
                }

                $ButtonType = [System.Windows.MessageBoxButton]::Ok
                $MessageIcon = [System.Windows.MessageBoxImage]::Information
                $MessageBody = "Usuario creado."
                $MessageTitle = "Mensaje"
                $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
                ($Form.close())
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
                $MessageBody = "Error: `n$message_Error `nNo se va a realizar ninguna acción."
                $MessageTitle = "Campos no válidos"
                [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
            }

        }  
     })
     # -------------------------------------------------------------------------------------------------------------------------------------------------------------
     

    #region Logic 

    #endregion

    [void]$Form.ShowDialog()

}