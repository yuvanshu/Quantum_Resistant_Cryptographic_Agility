# Quantum_Resistant_Cryptographic_Agility

This repository provides a Python-based framework for exploring cryptographic agility using various algorithms, including quantum-resistant post-quantum cryptography (PQC) schemes and classical encryption methods. The framework includes AES-256, Kyber (KEM), Dilithium (DSS), and Krypton for encryption, signing, and key exchange.

## Features ##
- **AES-256 Encryption/Decryption**: Secure symmetric encryption.
- **Kyber**: Post-quantum key encapsulation mechanism.
- **Dilithium**: Post-quantum digital signatures.
- **Krypton**: Symmetric encryption with verification support.
- **Performance Benchmarking**: Execution time and memory usage monitoring for cryptographic operations.

## Setup Instructions

1. Ensure Python 3.12 is installed.
2. Use a virtual environment for dependency management:

- **Conda**
    ```bash
    conda create -n crypto_env python=3.12
    conda activate crypto_env

- **Python Virtual Environment**
    ```bash
    python3.12 -m venv crypto_env
    source crypto_env/bin/activate  On Windows: .\crypto_env\Scripts\activate

3. Install the required quantcrypt library:
    ```bash
    pip install quantcrypt

## Usage ##
To demonstrate cryptographic agility using the provided framework, run the main script:

```bash
python c_a_class.py
```
    
You can modify the main() function in the script to experiment with these algorithms or to integrate additional cryptographic methods.
