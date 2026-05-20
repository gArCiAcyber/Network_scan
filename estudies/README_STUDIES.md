# hylianscan v0.4 - Guia de Estudos

## O que foi alterado

A versão v0.4 evolui o `hylianscan` em duas frentes principais:

1. Melhorias de entrada no terminal com `readline`.
2. Melhorias no scanner TCP com URLs clicáveis e probing ativo para serviços web.

No `hylianscan.py`, foi adicionada a biblioteca nativa `readline` para melhorar a experiência do prompt no Kali Linux. Isso permite usar setas, backspace e navegação de cursor de forma natural no terminal Bash.

No `modules/tcp_scanner.py`, o banner grabbing deixou de depender apenas de `recv()` passivo para portas web. Agora, portas como `80`, `443`, `8080`, `8000` e `8443` podem receber uma requisição HTTP leve do tipo `HEAD / HTTP/1.1`, forçando servidores web a responderem com headers úteis.

Também foi adicionada a geração de URLs web associadas a portas abertas:

- `80` -> `http://IP`
- `443` -> `https://IP`
- `8080`, `8000`, `8443` -> `http://IP:PORTA`

A renderização visual dessas URLs deve ficar na camada de interface/painel, usando ANSI Cyan.

## Por que a mudança foi necessária

### Problema do input no terminal

Sem `readline`, alguns terminais podem tratar teclas especiais como texto bruto.

Exemplos:

- seta para cima: `^[[A`
- seta para baixo: `^[[B`

Isso acontece porque setas e navegação de cursor não são caracteres comuns. Elas são sequências de escape ANSI enviadas pelo terminal.

Ao importar `readline`, o Python passa a usar o suporte nativo de edição de linha do Linux. Com isso, o prompt entende histórico, backspace, setas e movimentação de cursor sem poluir a tela.

### Problema do banner grabbing passivo

Apenas chamar `recv(1024)` funciona bem em serviços que enviam banner imediatamente, como alguns servidores SSH, FTP e SMTP.

Porém, muitos servidores HTTP ficam silenciosos até receberem uma requisição válida. Nesses casos, o scanner poderia mostrar:

```text
active (no banner)