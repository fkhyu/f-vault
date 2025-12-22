# f-vault

## Faru

This is my simple password manager made for Hack Club's Hackvault

## Overview

A simple terminal-based Python password manager with an intuitive UI. The application secures passwords using AES-GCM encryption with an Argon2-derived master key.

## Features

- **Master Password Authentication**: On first launch, set a master password that's confirmed on re-entry
- **Encrypted Vault**: Passwords and metadata stored in encrypted `.bin` file (JSON format)
- **Automatic Encryption/Decryption**: Vault decrypted on access, re-encrypted after changes
- **Terminal UI**: Interactive command-line interface with keyboard navigation

## Technologies

- **Encryption**: AES-GCM (via `cryptography`)
- **Key Derivation**: Argon2
- **Dependencies**: `cryptography`, `argon2-cffi`, `termcolor`, `bullet`, `pyperclip`
