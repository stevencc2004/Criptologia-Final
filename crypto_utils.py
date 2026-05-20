"""
Módulo: crypto_utils.py
Asignatura: Criptología - Proyecto Final (EduChain)
Universidad Distrital Francisco José de Caldas

Este módulo provee las primitivas criptográficas esenciales del sistema, incluyendo:
1. Hashing SHA-256 para bloques y transacciones.
2. Generación de pares de claves ECDSA sobre la curva elíptica SECP256K1.
3. Serialización de claves públicas en formato estándar X9.62 (sin comprimir, 130 caracteres hexadecimales con prefijo '04').
4. Emisión y verificación de firmas digitales ECDSA para garantizar autenticidad y no repudio.
"""

import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

def sha256_hash(data: str) -> str:
    """
    Calcula el hash SHA-256 de una cadena de texto.
    
    Args:
        data (str): Datos de entrada.
        
    Returns:
        str: Representación hexadecimal de 64 caracteres del hash.
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def generate_key_pair():
    """
    Genera un nuevo par de claves ECDSA utilizando la curva SECP256K1.
    
    Returns:
        tuple: (private_key_object, pk_hex_string)
            - private_key_object: Objeto de la clave privada en memoria.
            - pk_hex_string: Clave pública serializada en formato X9.62 hexadecimal (130 caracteres, prefijo '04').
    """
    # Generar clave privada usando la curva SECP256K1
    private_key = ec.generate_private_key(ec.SECP256K1())
    
    # Obtener la clave pública asociada
    public_key = private_key.public_key()
    
    # Serializar la clave pública en formato X9.62 no comprimido
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    pk_hex = public_bytes.hex()
    return private_key, pk_hex

def sign_data(private_key, data: str) -> str:
    """
    Firma digitalmente una cadena de datos usando una clave privada ECDSA y SHA-256.
    
    Args:
        private_key: Objeto de la clave privada ECDSA.
        data (str): Cadena a firmar (payload canónico).
        
    Returns:
        str: Firma digital resultante en formato hexadecimal.
    """
    data_bytes = data.encode('utf-8')
    signature = private_key.sign(
        data_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    return signature.hex()

def verify_signature(pk_hex: str, data: str, signature_hex: str) -> bool:
    """
    Verifica una firma digital ECDSA dada la clave pública del emisor en formato X9.62.
    
    Args:
        pk_hex (str): Clave pública en formato hexadecimal de 130 caracteres (prefijo '04').
        data (str): Datos originales firmados.
        signature_hex (str): Firma digital en formato hexadecimal.
        
    Returns:
        bool: True si la firma es válida, False en caso contrario.
    """
    try:
        # Deserializar la clave pública a partir de los puntos X9.62
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            bytes.fromhex(pk_hex)
        )
        
        data_bytes = data.encode('utf-8')
        signature_bytes = bytes.fromhex(signature_hex)
        
        # Verificar la firma
        public_key.verify(
            signature_bytes,
            data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        # Cualquier error de deserialización o verificación de firma retorna False
        return False

# Bloque de prueba de funcionamiento autónomo
if __name__ == '__main__':
    print("==================================================")
    print("PRUEBA UNITARIA: crypto_utils.py")
    print("==================================================")
    
    # 1. Prueba de Hash SHA-256
    mensaje = "Sistemas Descentralizados y Criptología 2026"
    hash_msg = sha256_hash(mensaje)
    print(f"1. Hash SHA-256 de '{mensaje}':\n   -> {hash_msg}")
    assert len(hash_msg) == 64, "El hash debe tener 64 caracteres"
    
    # 2. Generación de Claves
    print("\n2. Generando par de claves ECDSA (SECP256K1)...")
    priv_key, pub_key_hex = generate_key_pair()
    print(f"   -> Clave Privada (Objeto en memoria): {priv_key}")
    print(f"   -> Clave Pública Hex (X9.62 uncompressed, len={len(pub_key_hex)}):")
    print(f"      {pub_key_hex}")
    
    assert pub_key_hex.startswith("04"), "La clave pública X9.62 no comprimida debe empezar con '04'"
    assert len(pub_key_hex) == 130, "La clave pública X9.62 no comprimida debe medir exactamente 130 caracteres"
    
    # 3. Firma Digital
    payload = "PROF_001|EST_999|Criptologia|4.8"
    print(f"\n3. Firmando payload académico canónico: '{payload}'")
    firma = sign_data(priv_key, payload)
    print(f"   -> Firma generada (hex, len={len(firma)}):\n      {firma}")
    
    # 4. Verificación Exitosa
    print("\n4. Verificando firma válida con la clave pública...")
    es_valido = verify_signature(pub_key_hex, payload, firma)
    print(f"   -> ¿Firma válida?: {es_valido}")
    assert es_valido is True, "La firma generada debe ser válida"
    
    # 5. Verificación Fallida (Datos alterados)
    payload_alterado = "PROF_001|EST_999|Criptologia|5.0"
    print(f"\n5. Verificando con datos alterados: '{payload_alterado}'")
    es_valido_alterado = verify_signature(pub_key_hex, payload_alterado, firma)
    print(f"   -> ¿Firma válida tras alteración?: {es_valido_alterado}")
    assert es_valido_alterado is False, "La firma debe fallar si los datos fueron alterados (Efecto Avalancha/Integridad)"
    
    # 6. Verificación Fallida (Clave ajena)
    _, pub_key_ajena = generate_key_pair()
    print("\n6. Verificando firma con clave pública de un tercero...")
    es_valido_ajena = verify_signature(pub_key_ajena, payload, firma)
    print(f"   -> ¿Firma válida con clave ajena?: {es_valido_ajena}")
    assert es_valido_ajena is False, "La firma debe fallar si se verifica con otra clave pública"
    
    print("\n[OK] ¡Todas las pruebas criptograficas basicas superadas con exito!")
    print("==================================================")
