# Take care of SecureString to a plain text string (readable)
function SecureStringToPlainString {
    # The aim is to minimize the exposure of sensitive information
    param (
        [SecureString]$SecureString
    )
    # Way of representing string in windows API
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    # Automatically determines whether to use Unicode or ANSI encoding based on the current system settings
    $PlainString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    # Clear any trace in memory stored in $BSTR
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    return $PlainString
}

# Password validation function
function validatePassword {
    param (
        [SecureString]$PasswordSecured
    )
    # Convert SecureString to plain text
    $Password = SecureStringToPlainString -SecureString $PasswordSecured
    # Define regular expressions for each requirement
    # Check for at least one uppercase
    $uppercaseRegex = "[A-Z]"
    # Check for at least one lowercase
    $lowercaseRegex = "[a-z]"
    # Check for at least one number
    $numberRegex = "\d"
    # Check for at least one special character
    $specialCharRegex = '[!@#\$%\^&*()_+\-=\[\]{};:\",<>\./?\\|`~]'

    # Counter to check if password contains specified requirements
    $requirementsMet = 0

    # Check the length of the password
    if ($Password.Length -lt 12) {
        return $false
    }
    
    # Count how many requirements are met
    $requirementsMet = 0

    # Add requirement value if password meets some of the conditions
    if ($Password -cmatch $uppercaseRegex) {
        $requirementsMet++
    }
    if ($Password -cmatch $lowercaseRegex) {
        $requirementsMet++
    }
    if ($Password -cmatch $numberRegex) {
        $requirementsMet++
    }
    if ($Password -cmatch $specialCharRegex) {
        $requirementsMet++
    }
    
    # Check if at least three requirements are met
    if ($requirementsMet -lt 3) {
        return $false
    }
    
    # Password meets all requirements
    return $true
}

# Check password is the same as new password
function ValidateComparePassword {
    param (
        [SecureString]$NewPassword,
        [SecureString]$RepeatPassword
    )

    $plainNewPassword = SecureStringToPlainString -SecureString $NewPassword
    $plainRepeatPassword = SecureStringToPlainString -SecureString $RepeatPassword

    if ($plainNewPassword -ceq $plainRepeatPassword) {
        return $true
    } else {
        return $false
    }
}

# Check Patter for DNI and NIE
function checkPatternID {
    param (
        $ID
    )

    # Define the pattern for DNI and NIE
    # DNI: At start must contain 8 numbers followed by a uppercase letter
    # NIE: At start must contain a letter between XYZ, 7 numbers and an uppercase letter
    $patternDNI = "^\d{8}[A-Z]$"
    $patternNIE = "^[XYZ]\d{7}[A-Z]$"
    
    if ($ID -cmatch $patternDNI -or $ID -cmatch $patternNIE) {
        return $true
    } else {
        return $false
    }
}

# Search and check ID in AD if exist
function validateID {
    # Consults DNI
    param (
        $ID
    )

    $checkID = Get-ADUser -Filter {EmployeeID -eq $ID} -Property EmployeeID
    
    if($checkID -eq $null) {
        return $true
    } else {
        return $false
    }
    
}

# Search and checks if username exist
function validateUsername {
    # Consults DNI
    param (
        $username
    )

    $checkUsername = Get-ADUser -Filter {SamAccountName -eq $username} -Property SamAccountName

    if($checkUsername -eq $null -or $checkUsername -eq "") {
        return $true
    } else {
        return $false
    }
    
}

# Function to validate username using regex
function checkPatternUsername {
    param (
        [string]$username
    )
    
    <# 
    allows letters (both uppercase and lowercase), numbers, and specific characters for the username, 
    but it ensures that there are no vowels with accents in the username 
    #>
    $usernameRegex = '^[a-zA-Z0-9._%+-]+(?![aeiouAEIOU])$'
    $regex = New-Object System.Text.RegularExpressions.Regex($usernameRegex)

    $validateUsername = $regex.IsMatch($username)
    return $validateUsername
}

# Function to validate email using regex
function validateEmail {
    param (
        [string]$email
    )

    <#
     Allow only letters (both uppercase and lowercase), numbers, and a few specific characters in the local part of the email. 
     The domain part allows letters, numbers, and hyphens. It enforces a minimum of two characters in the top-level domain.
    #>
    $emailRegex = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    $regex = New-Object System.Text.RegularExpressions.Regex($emailRegex)

    $validateEmail = $regex.IsMatch($email)
    return $validateEmail
}