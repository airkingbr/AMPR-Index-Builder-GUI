# AMPR Index Builder GUI

Interface gráfica (Tkinter) para gerar o índice `ampr_emu.index`, usado pelo
resolver de arquivos APR do emulador AMPR (`/app0`).

## Funcionalidades

- Selecione a **Pasta do Jogo (Dump)** e gere o `ampr_emu.index` diretamente
  dentro dela (`<pasta>/ampr_emu.index`).
- Suporte a indexação de uma raiz local ou de um servidor FTP
  (`ftp://usuario:senha@host/caminho`).
- Opção para permitir colisões de nomes que diferem apenas por
  maiúsculas/minúsculas.
- Detecção automática da versão do `fakelib/libSceAmpr.sprx` com base no
  hash SHA-256 do arquivo.
- Botão para atualizar/substituir o `fakelib/libSceAmpr.sprx` a partir de
  qualquer arquivo selecionado (o arquivo é copiado e renomeado
  automaticamente para `libSceAmpr.sprx`).
- Log em tempo real da execução.

## Executando a partir do código-fonte

```bash
python gui_ampr_index.py
```

Requer Python 3.11+ (usa `from __future__ import annotations` e tipos
genéricos `list[...]`/`dict[...]`).

## Gerando o executável único (.exe)

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name AmprIndexBuilder gui_ampr_index.py
```

O executável será gerado em `dist/AmprIndexBuilder.exe`.
