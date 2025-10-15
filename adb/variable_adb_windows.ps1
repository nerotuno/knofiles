# SCRIPT POWERSHELL PARA ADICIONAR PLATFORM-TOOLS NA RAIZ DO DISCO C:

# 1. Define o caminho exato (C:\platform-tools)
$PlatformToolsPath = "C:\platform-tools"

# 2. Obtém a variável Path do USUÁRIO atual
# O escopo 'User' é o equivalente a usar SETX sem o modificador /M
$CurrentPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')

# 3. Adiciona o novo caminho à variável Path do USUÁRIO (permanente)
Write-Host "Adicionando $PlatformToolsPath à variável Path do USUÁRIO..."

# Verifica se o caminho já existe para evitar duplicatas
if ($CurrentPath -notcontains $PlatformToolsPath) {
    # Concatena o novo caminho ao Path existente
    $NewPath = "$CurrentPath;$PlatformToolsPath"
    
    # Define o novo valor da variável Path no escopo 'User'
    [System.Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
    
    Write-Host ""
    Write-Host "========================================================="
    Write-Host "SUCESSO! Caminho enviado para a variavel de ambiente Path."
    Write-Host "========================================================="
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "=========================================================================="
    Write-Host "ATENÇÃO: O caminho $PlatformToolsPath já existe na variável Path do USUÁRIO."
    Write-Host "=========================================================================="
    Write-Host ""
}

# 4. Mensagem de atenção (igual ao original)
Write-Host "ATENÇÃO: Você DEVE FECHAR e ABRIR novamente o Prompt de Comando ou PowerShell"
Write-Host "para que a alteração entre em vigor."
Write-Host ""

Pause
