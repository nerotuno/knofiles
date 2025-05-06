# Path to the folder where ADB is located
$adbPath = "C:\YourPath\platform-tools"  # <--- **ATTENTION: Replace with your actual path**

# Name of the environment variable
$envName = "Path"

# Value to be added to the environment variable
$newValue = ";$adbPath"

# Check if the environment variable already exists
$pathEnv = [Environment]::GetEnvironmentVariable($envName, "User")

# Check if the ADB path is already in the Path variable
if ($pathEnv -notlike "*$adbPath*") {
    # Add the ADB path to the Path variable
    [Environment]::SetEnvironmentVariable($envName, ($pathEnv + $newValue), "User")
    Write-Host "Environment variable '$envName' updated with the ADB path."

    # Inform that a terminal restart might be needed
    Write-Host "You might need to restart your terminal (PowerShell, CMD) for the changes to take effect."
} else {
    Write-Host "The ADB path is already configured in the environment variable '$envName'."
}
