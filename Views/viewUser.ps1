#Edit user function ------------------------------------------------------
function viewUser {
    param (
        $identity
    )

    #Extracts All Properties by SID
    $getUser = Get-ADUser -Identity $identity -Properties *
    $Actualnombre = $getUser.givenName
    $Actualapellidos = $getUser.Surname
    $ActualID = $getUser.EmployeeID
    $Actualusuario = $getUser.UserPrincipalName
    $Actualemail = $getUser.mail
    $Actualdescription = $getUser.Description
    $Actualoffice = $getUser.Office
    $Actualtitle = $getUser.Title
    $Actualdepartment = $getUser.Department
    $Actualcompany = $getUser.Company
    $ActualDN = $getUser.distinguishedName

    $fullDistinguishedName = $ActualDN
    $fullDistinguishedNameParts = $fullDistinguishedName -split "," | Select-Object -Skip 1
    $DNString = $fullDistinguishedNameParts -join ','

    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $Form                            = New-Object system.Windows.Forms.Form
    $Form.ClientSize                 = New-Object System.Drawing.Point(580,650)
    $Form.text                       = "Información"
    $Form.TopMost                    = $false
    $Form.FormBorderStyle            = "FixedDialog"
    $Form.MaximizeBox                = $false
    
	# Nombre
    $TBNombre                        = New-Object system.Windows.Forms.TextBox
    $TBNombre.multiline              = $false
    $TBNombre.width                  = 200
    $TBNombre.height                 = 20
    $TBNombre.ReadOnly               = $true
    $TBNombre.location               = New-Object System.Drawing.Point(135,50)
    $TBNombre.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBNombre.Text = $Actualnombre

    $LblNombre                       = New-Object system.Windows.Forms.Label
    $LblNombre.text                  = "Nombre:"
    $LblNombre.AutoSize              = $true
    $LblNombre.width                 = 25
    $LblNombre.height                = 10
    $LblNombre.location              = New-Object System.Drawing.Point(35,50)
    $LblNombre.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Apellidos
    $TBApellidos                        = New-Object system.Windows.Forms.TextBox
    $TBApellidos.multiline              = $false
    $TBApellidos.width                  = 200
    $TBApellidos.height                 = 20
    $TBApellidos.ReadOnly               = $true
    $TBApellidos.location               = New-Object System.Drawing.Point(135,100)
    $TBApellidos.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBApellidos.Text = $Actualapellidos

    $LblApellidos                    = New-Object system.Windows.Forms.Label
    $LblApellidos.text               = "Apellidos:"
    $LblApellidos.AutoSize           = $true
    $LblApellidos.width              = 25
    $LblApellidos.height             = 10
    $LblApellidos.location           = New-Object System.Drawing.Point(35,100)
    $LblApellidos.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # ID
    $TBID                        = New-Object system.Windows.Forms.TextBox
    $TBID.multiline              = $false
    $TBID.width                  = 150
    $TBID.height                 = 20
    $TBID.ReadOnly               = $true
    $TBID.location               = New-Object System.Drawing.Point(135,150)
    $TBID.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBID.text = $ActualID

    $LblID                       = New-Object system.Windows.Forms.Label
    $LblID.text                  = "DNI/NIE:"
    $LblID.AutoSize              = $true
    $LblID.width                 = 25
    $LblID.height                = 10
    $LblID.location              = New-Object System.Drawing.Point(35,150)
    $LblID.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Usuario
    $TBUsuario                        = New-Object system.Windows.Forms.TextBox
    $TBUsuario.multiline              = $false
    $TBUsuario.width                  = 200
    $TBUsuario.height                 = 20
    $TBUsuario.ReadOnly               = $true
    $TBUsuario.location               = New-Object System.Drawing.Point(135,200)
    $TBUsuario.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBUsuario.text = $Actualusuario

    $LblUsuario                       = New-Object system.Windows.Forms.Label
    $LblUsuario.text                  = "Usuario:"
    $LblUsuario.AutoSize              = $true
    $LblUsuario.width                 = 25
    $LblUsuario.height                = 10
    $LblUsuario.location              = New-Object System.Drawing.Point(35,200)
    $LblUsuario.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Email
    $TBemail                        = New-Object system.Windows.Forms.TextBox
    $TBemail.multiline              = $false
    $TBemail.width                  = 200
    $TBemail.height                 = 20
    $TBemail.ReadOnly               = $true
    $TBemail.location               = New-Object System.Drawing.Point(135,250)
    $TBemail.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBemail.text = $Actualemail

    $LblEmail                       = New-Object system.Windows.Forms.Label
    $LblEmail.text                  = "Correo externo:"
    $LblEmail.AutoSize              = $true
    $LblEmail.width                 = 25
    $LblEmail.height                = 10
    $LblEmail.location              = New-Object System.Drawing.Point(35,250)
    $LblEmail.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Description
    $TBDescription                        = New-Object system.Windows.Forms.TextBox
    $TBDescription.multiline              = $false
    $TBDescription.width                  = 400
    $TBDescription.height                 = 20
    $TBDescription.ReadOnly               = $true
    $TBDescription.location               = New-Object System.Drawing.Point(135,300)
    $TBDescription.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBDescription.text = $Actualdescription

    $LblDescription                      = New-Object system.Windows.Forms.Label
    $LblDescription.text                  = "Descripción:"
    $LblDescription.AutoSize              = $true
    $LblDescription.width                 = 25
    $LblDescription.height                = 10
    $LblDescription.location              = New-Object System.Drawing.Point(35,300)
    $LblDescription.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Office
    $TBOffice                        = New-Object system.Windows.Forms.TextBox
    $TBOffice.multiline              = $false
    $TBOffice.width                  = 400
    $TBOffice.height                 = 20
    $TBOffice.ReadOnly               = $true
    $TBOffice.location               = New-Object System.Drawing.Point(135,350)
    $TBOffice.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBOffice.Text = $Actualoffice

    $LblOffice                      = New-Object system.Windows.Forms.Label
    $LblOffice.text                  = "Oficina:"
    $LblOffice.AutoSize              = $true
    $LblOffice.width                 = 25
    $LblOffice.height                = 10
    $LblOffice.location              = New-Object System.Drawing.Point(35,350)
    $LblOffice.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Title
    $TBTitle                        = New-Object system.Windows.Forms.TextBox
    $TBTitle.multiline              = $false
    $TBTitle.width                  = 400
    $TBTitle.height                 = 20
    $TBTitle.ReadOnly               = $true
    $TBTitle.location               = New-Object System.Drawing.Point(135,400)
    $TBTitle.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBTitle.text = $Actualtitle

    $LblTitle                      = New-Object system.Windows.Forms.Label
    $LblTitle.text                  = "Título:"
    $LblTitle.AutoSize              = $true
    $LblTitle.width                 = 25
    $LblTitle.height                = 10
    $LblTitle.location              = New-Object System.Drawing.Point(35,400)
    $LblTitle.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Department
    $TBDepartment                        = New-Object system.Windows.Forms.TextBox
    $TBDepartment.multiline              = $false
    $TBDepartment.width                  = 400
    $TBDepartment.height                 = 20
    $TBDepartment.ReadOnly               = $true
    $TBDepartment.location               = New-Object System.Drawing.Point(135,450)
    $TBDepartment.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBDepartment.text = $Actualdepartment

    $LblDepartment                      = New-Object system.Windows.Forms.Label
    $LblDepartment.text                  = "Departamento:"
    $LblDepartment.AutoSize              = $true
    $LblDepartment.width                 = 25
    $LblDepartment.height                = 10
    $LblDepartment.location              = New-Object System.Drawing.Point(35,450)
    $LblDepartment.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Company
    $TBCompany                        = New-Object system.Windows.Forms.TextBox
    $TBCompany.multiline              = $false
    $TBCompany.width                  = 400
    $TBCompany.height                 = 20
    $TBCompany.ReadOnly               = $true
    $TBCompany.location               = New-Object System.Drawing.Point(135,500)
    $TBCompany.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBCompany.Text = $Actualcompany

    $LblCompany                      = New-Object system.Windows.Forms.Label
    $LblCompany.text                  = "Compañia:"
    $LblCompany.AutoSize              = $true
    $LblCompany.width                 = 25
    $LblCompany.height                = 10
    $LblCompany.location              = New-Object System.Drawing.Point(35,500)
    $LblCompany.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # OU
    $TBOU                        = New-Object system.Windows.Forms.TextBox
    $TBOU.multiline              = $false
    $TBOU.width                  = 400
    $TBOU.height                 = 20
    $TBOU.ReadOnly               = $true
    $TBOU.location               = New-Object System.Drawing.Point(135,550)
    $TBOU.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $TBOU.Text = $DNString

    $LblOU                       = New-Object system.Windows.Forms.Label
    $LblOU.text                  = "OU:"
    $LblOU.AutoSize              = $true
    $LblOU.width                 = 25
    $LblOU.height                = 10
    $LblOU.location              = New-Object System.Drawing.Point(35,550)
    $LblOU.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    # Aceptar
    $BotonCerrar                    = New-Object system.Windows.Forms.Button
    $BotonCerrar.text               = "Cerrar"
    $BotonCerrar.width              = 60
    $BotonCerrar.height             = 30
    $BotonCerrar.location           = New-Object System.Drawing.Point(250,600)
    $BotonCerrar.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $Form.controls.AddRange(@($TBNombre,$LblNombre,$TBApellidos,$LblApellidos,$TBID,$LblID,$LblUsuario,$TBUsuario, `
                            $LblEmail,$TBEmail,$LblDescription,$TBDescription,$LblOffice,$TBOffice,$LblTitle,$TBTitle, `
                            $LblDepartment,$TBDepartment,$LblCompany,$TBCompany,$LblOU,$TBOU,$BotonCerrar))


    # Button to close active form
    $BotonCerrar.Add_Click({
        $Form.Close()    
    })
    

    [void]$Form.ShowDialog()  
    

}
#----------------------------------------------------------------------------