# SCRIPT POWERSHELL PARA ADICIONAR PLATFORM-TOOLS NA RAIZ DO DISCO C:

# 1. Define o caminho exato (C:\platform-tools)
$PlatformToolsPath = "C:\platform-tools"

# 2. Obtém a variável Path do USUÁRIO atual
# O escopo 'User' é o equivalente a usar SETX sem o modificador /M
$CurrentPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')

# 3. Adiciona o novo caminho à variável Path do USUÁRIO (permanente)
Write-Host "Adding $PlatformToolsPath to the USER's Path variable..."

# Verifica se o caminho já existe para evitar duplicatas
if ($CurrentPath -notcontains $PlatformToolsPath) {
    # Concatena o novo caminho ao Path existente
    $NewPath = "$CurrentPath;$PlatformToolsPath"
    
    # Define o novo valor da variável Path no escopo 'User'
    [System.Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
    
    Write-Host ""
    Write-Host "========================================================="
    Write-Host "SUCCESS! Path sent to an environment variable Path."
    Write-Host "========================================================="
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "=========================================================================="
    Write-Host "WARNING: The path $PlatformToolsPath already exists in the USER's Path variable."
    Write-Host "=========================================================================="
    Write-Host ""
}

# 4. Mensagem de atenção (igual ao original)
Write-Host "WARNING: You MUST CLOSE and RE-OPEN the Command Prompt or PowerShell"
Write-Host "for the change to take effect."
Write-Host ""

# Comando adicionado para apagar o próprio arquivo de script
$MyInvocation.MyCommand.Path | Remove-Item -Force

Pause
