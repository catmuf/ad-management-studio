# Change password function--------------------------------------------------------
function ChangePassword {

    #Fetch a specific tag when an item is selected in listview form the main window.
    param(
        $identity,
        $identityName,
        $identityID
    )

    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $Form                            = New-Object system.Windows.Forms.Form
    $Form.ClientSize                 = New-Object System.Drawing.Point(400,300)
    $Form.text                       = "Cambiar clave"
    $Form.TopMost                    = $false
    $Form.FormBorderStyle            = "FixedDialog"
    $Form.MaximizeBox                = $false

    $LBUserDetails                   = New-Object system.Windows.Forms.Label
    $LBUserDetails.text              = "$identityName ($identityID)"
    $LBUserDetails.AutoSize          = $true
    $LBUserDetails.width             = 25
    $LBUserDetails.height            = 10
    $LBUserDetails.location          = New-Object System.Drawing.Point(30,30)
    $LBUserDetails.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LBNewPassword                   = New-Object system.Windows.Forms.Label
    $LBNewPassword.text              = "Nueva clave:"
    $LBNewPassword.AutoSize          = $true
    $LBNewPassword.width             = 25
    $LBNewPassword.height            = 10
    $LBNewPassword.location          = New-Object System.Drawing.Point(30,75)
    $LBNewPassword.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $SMSNewPassword                   = New-Object system.Windows.Forms.Label
    $SMSNewPassword.AutoSize          = $true
    $SMSNewPassword.width             = 25
    $SMSNewPassword.height            = 10
    $SMSNewPassword.location          = New-Object System.Drawing.Point(130,95)
    $SMSNewPassword.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $TBNewPassword                   = New-Object system.Windows.Forms.MaskedTextBox
    $TBNewPassword.PasswordChar      = '*'
    $TBNewPassword.multiline         = $false
    $TBNewPassword.width             = 200
    $TBNewPassword.height            = 20
    $TBNewPassword.location          = New-Object System.Drawing.Point(130,70)
    $TBNewPassword.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $LBRepeatPassword                = New-Object system.Windows.Forms.Label
    $LBRepeatPassword.text           = "Repetir Clave:"
    $LBRepeatPassword.AutoSize       = $true
    $LBRepeatPassword.width          = 25
    $LBRepeatPassword.height         = 10
    $LBRepeatPassword.location       = New-Object System.Drawing.Point(30,125)
    $LBRepeatPassword.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $SMSRepeatPassword                   = New-Object system.Windows.Forms.Label
    $SMSRepeatPassword.AutoSize          = $true
    $SMSRepeatPassword.width             = 25
    $SMSRepeatPassword.height            = 10
    $SMSRepeatPassword.location          = New-Object System.Drawing.Point(130,145)
    $SMSRepeatPassword.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $TBRepeatPassword                = New-Object system.Windows.Forms.MaskedTextBox
    $TBRepeatPassword.PasswordChar   = '*'
    $TBRepeatPassword.multiline      = $false
    $TBRepeatPassword.width          = 200
    $TBRepeatPassword.height         = 20
    $TBRepeatPassword.visible        = $true
    $TBRepeatPassword.location       = New-Object System.Drawing.Point(130,120)
    $TBRepeatPassword.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    # Create checkbox to toggle password visibility
    $CBShowPassword                          = New-Object System.Windows.Forms.CheckBox
    $CBShowPassword.Text                     = "Mostrar clave"
    $CBShowPassword.location                 = New-Object System.Drawing.Point(30,170)
    $CBShowPassword.height                   = 40
    $CBShowPassword.AutoSize                 = $true
    $CBShowPassword.Checked                  = $false
    $CBShowPassword.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)


    $CBChangePasswordNextLogin       = New-Object system.Windows.Forms.CheckBox
    $CBChangePasswordNextLogin.text  = "Cambiar la contraseña en el próximo inicio de sesión"
    $CBChangePasswordNextLogin.AutoSize  = $true
    $CBChangePasswordNextLogin.height  = 40
    $CBChangePasswordNextLogin.location  = New-Object System.Drawing.Point(30,200)
    $CBChangePasswordNextLogin.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    # Create a ToolTip ID
    $toolTip = New-Object Windows.Forms.ToolTip
    $toolTip.SetToolTip($TBNewPassword, "Debe contener al menos 12 caracteres y al menos tres de estas opciones:" +
                        "`n-Al menos una letra mayúscula" + "`n-Al menos una letra minúscula" + "`n-Al menos un número" +
                        "`n-Al menos un carácter especial"
                        )
    
    $BTConfirmar                       = New-Object system.Windows.Forms.Button
    $BTConfirmar.text                  = "Confirmar"
    $BTConfirmar.width                 = 80
    $BTConfirmar.height                = 30
    $BTConfirmar.location              = New-Object System.Drawing.Point(170,250)
    $BTConfirmar.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $BTConfirmar.Enabled               = $false

    $Form.controls.AddRange(@($LBUserDetails,$LBNewPassword,$TBNewPassword,$SMSNewPassword,$LBRepeatPassword,$TBRepeatPassword,$SMSRepeatPassword,$CBShowPassword,$CBChangePasswordNextLogin,$BTConfirmar))
    
    #Check password and new password inputs whenever there is a change
    $TBNewPassword.Add_TextChanged({
        confirmbuttonState
    })

    $TBRepeatPassword.Add_TextChanged({
        confirmbuttonState
    })
    
    # Show/Hide password
    $CBShowPassword.Add_CheckedChanged({
        if ($CBShowPassword.Checked) {
            $TBNewPassword.PasswordChar = 0
            $TBRepeatPassword.PasswordChar = 0
        } else {
            $TBNewPassword.PasswordChar = '*'
            $TBRepeatPassword.PasswordChar = '*'
        }
    })

    #Custom object to store states
    $State = [PSCustomObject]@{
        Password = $false
        RepeatPassword = $false
    }
    # Function to validate fields
    function confirmbuttonState{
            # ------------------------------------ Check wether input is empty/null ---------------------------------------------------------------------------------------
            if(![string]::IsNullOrWhiteSpace($TBNewPassword.Text.Trim())) {
                $newPassword = ConvertTo-SecureString $TBNewPassword.Text.Trim() -AsPlainText -Force

                #Validate password pattern from an external funtion
                $State.Password = validatePassword -password $newPassword

                # Show state of validation
                if($State.Password) {
                    $SMSNewPassword.Text = "Válido"
                    $SMSNewPassword.ForeColor = [System.Drawing.Color]::Green
                } else {
                    $SMSNewPassword.Text = "Inválido"
                    $SMSNewPassword.ForeColor = [System.Drawing.Color]::Red
                }

            }
            if(![string]::IsNullOrWhiteSpace($TBRepeatPassword.Text.Trim())) {
                $newPassword = ConvertTo-SecureString $TBNewPassword.Text.Trim() -AsPlainText -Force
                $repeatNewPassword = ConvertTo-SecureString $TBRepeatPassword.Text.Trim() -AsPlainText -Force

                #Validate new and repeated password from an external function
                $State.RepeatPassword = validateComparePassword -newpassword $newPassword -repeatPassword $repeatNewPassword

                # Show state of validation
                if($State.RepeatPassword) {
                    $SMSRepeatPassword.Text = "Coincide"
                    $SMSRepeatPassword.ForeColor = [System.Drawing.Color]::Green
                    
                } else {
                    $SMSRepeatPassword.Text = "No coincide"
                    $SMSRepeatPassword.ForeColor = [System.Drawing.Color]::Red
                }

            }
            
            # ---------------------------------------------------------------------------------------------------------------------------------------------------------------
            
            # Check password input states to enable button to proceed
                
                
            if($State.Password -and $State.RepeatPassword) {
                $BTConfirmar.Enabled = $true
            } else {
                $BTConfirmar.Enabled = $false
            }
            
            
    }

    # Button to apply new password
    $BTConfirmar.Add_Click({
        
        $ButtonType = [System.Windows.MessageBoxButton]::OkCancel
        $MessageIcon = [System.Windows.MessageBoxImage]::Warning
        $MessageBody = "¿Estás seguro de que quieres cambiar la contraseña de $identityName ($identityID)?"
        $MessageTitle = "Cambio de contraseña"
        $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)

        $Pass = ConvertTo-SecureString $TBRepeatPassword.Text.Trim() -AsPlainText -Force

        # Check decision
        if($Result -eq "Ok") {
            #Reset the account password
            Set-ADAccountPassword -identity $identity -NewPassword $Pass -Reset
            if($CBChangePasswordNextLogin.checked -eq $true) {
                #Force user to change password at next logon
                Set-ADUser -Identity $identity -ChangePasswordAtLogon $true
            } else {
                #Force user to change password at next logon
                Set-ADUser -Identity $identity -ChangePasswordAtLogon $false
            }

            $ButtonType = [System.Windows.MessageBoxButton]::Ok
            $MessageIcon = [System.Windows.MessageBoxImage]::Information
            $MessageBody = "Contraseña actualizada!"
            $MessageTitle = "Información"
            $Result = [System.Windows.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
                
            $Form.close()
        }
           
    })

    #region Logic 

    #endregion

    [void]$Form.ShowDialog()
}
#---------------------------------------------------------------------------------