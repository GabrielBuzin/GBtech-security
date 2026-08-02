# GBTech Security

Protótipo pessoal para Windows com monitoramento de pastas e quarentena reversível.

## O que ele faz

- Monitora pastas selecionadas continuamente.
- Isola arquivos que exigem revisão em uma quarentena local.
- Permite restaurar ou excluir itens sob confirmação.
- Mantém as contas apenas como referência local; senhas e chaves não são salvas.
- Continua monitorando quando a janela é minimizada.

## Como iniciar

Execute `iniciar-gbtech-security.bat` no Windows.

O aplicativo fica na área de notificação do Windows (perto do relógio) ao ser minimizado. Clique com o botão direito no ícone para reabrir ou encerrar o monitoramento.

Para executar em outro computador, instale as dependências uma vez com `python -m pip install -r requirements.txt`.

## Limites importantes

Este é um protótipo de segurança local, não um substituto para um antivírus comercial. Ele não bloqueia ameaças no nível do sistema e não envia arquivos para serviços externos.
