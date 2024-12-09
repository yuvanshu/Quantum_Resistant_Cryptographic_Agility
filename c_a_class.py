import secrets
import time
import tracemalloc
from quantcrypt.kem import Kyber  # Import Kyber for key encapsulation
from quantcrypt.dss import Dilithium  # Import Dilithium for digital signatures
from quantcrypt.cipher import Krypton  # Import Krypton for symmetric encryption
from Cryptodome.Cipher import AES  # Import AES for symmetric encryption

class CryptographicAgility:
    def __init__(self, algorithm_name):
        self.algorithm_name = algorithm_name
        self.kem = None
        self.dss = None
        self.cipher = None
        self.secret_key = None
        self.aes_key = None  # AES key
        self._initialize_algorithms()

    def _initialize_algorithms(self):
        """
        Initialize the selected PQC algorithms based on the provided algorithm name.
        """
        if self.algorithm_name == 'Kyber':
            self.kem = Kyber()  # Key Encapsulation with Kyber
        elif self.algorithm_name == 'Dilithium':
            self.dss = Dilithium()  # Digital Signature with Dilithium
        elif self.algorithm_name == 'Krypton':
            self.secret_key = secrets.token_bytes(64)  # Generate a 64-byte secret key for Krypton
            self.cipher = Krypton(self.secret_key)  # Initialize Krypton with the secret key
        elif self.algorithm_name == 'AES-256':
            self.aes_key = secrets.token_bytes(32)  # AES-256 requires a 256-bit (32-byte) key
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm_name}")
    
    def benchmark(self, func, *args):
        """
        Helper function to measure execution time.
        """
        start_time = time.time()
        result = func(*args)
        elapsed_time = time.time() - start_time
        return result, elapsed_time
    
    def memory_benchmark(self, func, *args):
        """
        Benchmark memory usage and execution time of a function.
        """
        tracemalloc.start()
        start_time = time.time()
        result = func(*args)
        elapsed_time = time.time() - start_time
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        print(f"Function: {func.__name__}")
        print(f"Execution time: {elapsed_time:.6f} seconds")
        print(f"Peak memory usage: {peak / 1024:.2f} KB")
        return result, elapsed_time, peak / 1024  # Return result and metrics
    
    def aes_encrypt(self, data):
        """
        Encrypt data using AES-256 and benchmark performance.
        """
        if self.aes_key:
            def encrypt_aes():
                cipher = AES.new(self.aes_key, AES.MODE_GCM)  # AES in GCM mode
                nonce = cipher.nonce  # Nonce for AES encryption
                ciphertext, tag = cipher.encrypt_and_digest(data)  # Encrypt and create a tag

                return nonce, ciphertext, tag

            # Apply memory benchmarking
            (nonce, ciphertext, tag), enc_time, enc_memory = self.memory_benchmark(encrypt_aes)
            print(f"AES Encryption: Time = {enc_time:.6f} s, Memory = {enc_memory:.2f} KB")
            print(f"Data encrypted successfully with AES-256. Ciphertext: {ciphertext.hex()[:16]}...")
            return nonce, ciphertext, tag
        else:
            raise NotImplementedError("AES encryption not available for the selected algorithm.")


    def aes_decrypt(self, nonce, ciphertext, tag):
        """
        Decrypt ciphertext using AES-256 and benchmark performance.
        """

        if self.aes_key:
            def decrypt_aes():
                cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)  # AES in GCM mode
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify tag
                return plaintext

            # Apply memory benchmarking
            plaintext, dec_time, dec_memory = self.memory_benchmark(decrypt_aes)
            print(f"AES Decryption: Time = {dec_time:.6f} s, Memory = {dec_memory:.2f} KB")
            print("Data decrypted successfully with AES-256.")
            return plaintext
        else:
            raise NotImplementedError("AES decryption not available for the selected algorithm.")


    def pqc_key_exchange(self):
        """
        Perform key exchange using Kyber (or other KEMs).
        """
        if self.kem:
            print(f"\nUsing PQC Algorithm: {self.algorithm_name}")
            
            # Measure key generation
            (public_key, secret_key), gen_time, gen_memory = self.memory_benchmark(self.kem.keygen)
            print(f"Key Generation: Time = {gen_time:.6f} s, Memory = {gen_memory:.2f} KB")
            
            # Measure encapsulation
            (cipher_text, shared_secret_client), encap_time, encap_memory = self.memory_benchmark(
                self.kem.encaps, public_key
            )
            print(f"Encapsulation: Time = {encap_time:.6f} s, Memory = {encap_memory:.2f} KB")
            
            # Measure decapsulation
            shared_secret_server, decap_time, decap_memory = self.memory_benchmark(
                self.kem.decaps, secret_key, cipher_text
            )
            print(f"Decapsulation: Time = {decap_time:.6f} s, Memory = {decap_memory:.2f} KB")
            
            assert shared_secret_client == shared_secret_server, "Key exchange failed!"
            return shared_secret_server
        else:
            raise NotImplementedError("Key exchange not implemented for the selected algorithm.")

    def pqc_sign_data(self, message):
        """
        Sign data using Dilithium or other signature algorithms.
        """
        if self.dss:
            print(f"\nSigning Data Using PQC Algorithm: {self.algorithm_name}")
            
            # Measure key generation
            (public_key, secret_key), gen_time, gen_memory = self.memory_benchmark(self.dss.keygen)
            print(f"Key Generation: Time = {gen_time:.6f} s, Memory = {gen_memory:.2f} KB")
            
            # Measure signing
            signature, sign_time, sign_memory = self.memory_benchmark(self.dss.sign, secret_key, message)
            print(f"Signing: Time = {sign_time:.6f} s, Memory = {sign_memory:.2f} KB")
            
            return public_key, signature
        else:
            raise NotImplementedError("Signing not implemented for the selected algorithm.")

    def pqc_verify_signature(self, public_key, message, signature):
        """
        Verify signature using Dilithium or other signature algorithms.
        """
        if self.dss:
            is_valid, verify_time, verify_memory = self.memory_benchmark(
                self.dss.verify, public_key, message, signature
            )
            print(f"Verification: Time = {verify_time:.6f} s, Memory = {verify_memory:.2f} KB")
            return is_valid
        else:
            raise NotImplementedError("Verification not implemented for the selected algorithm.")


    def krypton_encrypt(self, data):
        """
        Encrypt data using Krypton with the internal secret key.
        """
        if self.cipher:
            print("\nUsing Krypton for encryption")
            self.cipher.begin_encryption()  # Begin encryption
            ciphertext = self.cipher.encrypt(data)  # Encrypt the data
            verif_dp = self.cipher.finish_encryption()  # Generate the verification data packet
            print(f"Data encrypted successfully. Ciphertext: {ciphertext.hex()[:16]}...")
            return ciphertext, verif_dp
        else:
            raise NotImplementedError("Encryption not implemented for the selected algorithm.")

    def krypton_decrypt(self, ciphertext, verif_dp):
        """
        Decrypt ciphertext using Krypton with the internal secret key and verification data.
        """
        if self.cipher:
            self.cipher.begin_decryption(verif_dp)  # Begin decryption with the verification data packet
            plaintext = self.cipher.decrypt(ciphertext)  # Decrypt the ciphertext
            self.cipher.finish_decryption()  # Verify decryption validity
            return plaintext
        else:
            raise NotImplementedError("Decryption not implemented for the selected algorithm.")

# Main function demonstrating cryptographic agility
def main():
    message = b"Hello"
    data = 'Hello'

    # Example of choosing AES-256 for encryption
    crypto_aes = CryptographicAgility(algorithm_name="AES-256")
    nonce, ciphertext_aes, tag = crypto_aes.aes_encrypt(data.encode())  # AES encryption

    # Example of choosing the Kyber algorithm for key exchange
    crypto_kyber = CryptographicAgility(algorithm_name="Kyber")
    shared_key = crypto_kyber.pqc_key_exchange()  # Perform Kyber-based key exchange

    # Example of choosing Krypton for encryption with the internal secret key
    crypto_krypton = CryptographicAgility(algorithm_name="Krypton")
    ciphertext_krypton, verif_dp = crypto_krypton.krypton_encrypt(data)  # Krypton encryption

    # Example of choosing Dilithium for signing
    crypto_dilithium = CryptographicAgility(algorithm_name="Dilithium")
    public_key, signature = crypto_dilithium.pqc_sign_data(ciphertext_krypton)  # Sign the ciphertext with Dilithium

    # Verify the signature
    is_valid = crypto_dilithium.pqc_verify_signature(public_key, ciphertext_krypton, signature)  # Verify the signature
    if not is_valid:
        print("Warning: Data integrity check failed!")
        return

    # # Decrypt the data using Krypton after verifying the signature
    decrypted_data = crypto_krypton.krypton_decrypt(ciphertext_krypton, verif_dp)  # Krypton decryption
    print(f"\nDecrypted data using Krypton: {decrypted_data.decode()}\n")

    # Decrypt the data using AES-256 after verifying the signature
    decrypted_data = crypto_aes.aes_decrypt(nonce, ciphertext_aes, tag)  # AES decryption
    print(f"\nDecrypted data using AES-256: {decrypted_data.decode()}\n")

if __name__ == "__main__":
    main()
