# Disable user funstion using user´s DistinguisheName
function DisableUser {
    param(
        $identity
    )
    # User´s SID
    Disable-ADAccount -Identity $identity
    Move-ADObject -Identity $identity -TargetPath $ADdisableUser
}