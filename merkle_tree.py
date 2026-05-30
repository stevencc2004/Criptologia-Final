"""
Módulo: merkle_tree.py
Asignatura: Criptología - Proyecto Final 
Universidad Distrital Francisco José de Caldas

Este módulo implementa la estructura del Árbol de Merkle para agrupar transacciones
académicas de forma compacta y criptográficamente segura.
"""

from crypto_utils import sha256_hash

def get_payload_from_tx(tx) -> str:
    """
    Extrae el payload canónico de un objeto de transacción, soportando múltiples
    estructuras (Objetos con método, Diccionarios o Listas).
    
    Args:
        tx: Transacción en cualquier formato compatible.
        
    Returns:
        str: Payload canónico formateado 'ID_Profesor|ID_Estudiante|Asignatura|Nota'.
    """
    if hasattr(tx, 'get_canonical_payload'):
        return tx.get_canonical_payload()
    elif isinstance(tx, dict):
        return f"{tx.get('id_profesor')}|{tx.get('id_estudiante')}|{tx.get('asignatura')}|{tx.get('nota')}"
    elif isinstance(tx, (list, tuple)) and len(tx) >= 4:
        return f"{tx[0]}|{tx[1]}|{tx[2]}|{tx[3]}"
    else:
        return str(tx)

def compute_merkle_root(transactions: list) -> str:
    """
    Calcula la raíz del árbol de Merkle sobre una lista de transacciones.
    
    Args:
        transactions (list): Lista de transacciones.
        
    Returns:
        str: Raíz de Merkle de 64 caracteres en hexadecimal.
    """
    # Caso 0: Lista vacía (Bloque Génesis)
    if not transactions:
        return "0" * 64

    # Obtener el hash SHA-256 del payload canónico de cada transacción (Hojas)
    leaves = [sha256_hash(get_payload_from_tx(tx)) for tx in transactions]

    # Caso 1: Una sola transacción.
    # "El árbol de 1 hoja debe retornar SHA-256 de esa hoja directamente."
    if len(leaves) == 1:
        return leaves[0]

    # Construcción interactiva hacia la raíz (árbol binario)
    current_level = leaves
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            if i + 1 < len(current_level):
                right = current_level[i + 1]
            else:
                # Si el número de nodos en este nivel es impar, duplicamos el último nodo
                right = left
            
            # Combinar hashes adyacentes
            parent_hash = sha256_hash(left + right)
            next_level.append(parent_hash)
        current_level = next_level

    return current_level[0]

# Bloque de prueba de funcionamiento autónomo
if __name__ == '__main__':
    try:
        print("==================================================")
        print("PRUEBA UNITARIA: merkle_tree.py")
        print("==================================================")

        # Definimos transacciones de prueba en formato lista [ID_Profesor, ID_Estudiante, Asignatura, Nota]
        tx1 = ["PROF_01", "EST_01", "Criptologia", 4.5]
        tx2 = ["PROF_01", "EST_02", "Criptologia", 3.8]
        tx3 = ["PROF_01", "EST_03", "Criptologia", 5.0]
        tx4 = ["PROF_01", "EST_04", "Criptologia", 4.2]

        # 1. Prueba con 0 transacciones (Génesis)
        root_0 = compute_merkle_root([])
        print(f"1. Merkle Root con 0 transacciones:\n   -> {root_0}")
        if root_0 != "0" * 64:
            raise AssertionError("Génesis debe dar 64 ceros")

        # 2. Prueba con 1 transacción
        root_1 = compute_merkle_root([tx1])
        hash_single_tx = sha256_hash(get_payload_from_tx(tx1))
        print(f"\n2. Merkle Root con 1 transacción:\n   -> {root_1}")
        print(f"   -> Hash esperado (directo de la hoja): {hash_single_tx}")
        if root_1 != hash_single_tx:
            raise AssertionError("La raíz de una sola hoja debe ser el hash de esa hoja")

        # 3. Prueba con 2 transacciones (Par)
        root_2 = compute_merkle_root([tx1, tx2])
        h1 = sha256_hash(get_payload_from_tx(tx1))
        h2 = sha256_hash(get_payload_from_tx(tx2))
        expected_root_2 = sha256_hash(h1 + h2)
        print(f"\n3. Merkle Root con 2 transacciones:\n   -> {root_2}")
        print("   -> Hashes hoja usados en el recorrido:")
        print(f"      H1 = sha256(payload(tx1)) = {h1}")
        print(f"      H2 = sha256(payload(tx2)) = {h2}")
        print(f"   -> Hash del padre calculado con H1 + H2: {expected_root_2}")
        if root_2 != expected_root_2:
            raise AssertionError("Cálculo incorrecto para 2 hojas")

        # 4. Prueba con 3 transacciones (Impar, duplicando última hoja)
        root_3 = compute_merkle_root([tx1, tx2, tx3])
        h3 = sha256_hash(get_payload_from_tx(tx3))
        # Nivel 1: [H12 = H(H1+H2), H33 = H(H3+H3)]
        h12 = sha256_hash(h1 + h2)
        h33 = sha256_hash(h3 + h3)
        # Nivel 2 (Root): H(H12 + H33)
        expected_root_3 = sha256_hash(h12 + h33)
        print(f"\n4. Merkle Root con 3 transacciones:\n   -> {root_3}")
        print("   -> Nivel 1 del recorrido:")
        print(f"      H12 = sha256(H1 + H2) = {h12}")
        print(f"      H33 = sha256(H3 + H3) = {h33}  <- H3 duplicado por ser impar")
        print("   -> Nivel 2 del recorrido (raíz):")
        print(f"      root = sha256(H12 + H33) = {expected_root_3}")
        if root_3 != expected_root_3:
            raise AssertionError("Cálculo incorrecto para número impar de hojas")

        # 5. Prueba con 4 transacciones (Par)
        root_4 = compute_merkle_root([tx1, tx2, tx3, tx4])
        h4 = sha256_hash(get_payload_from_tx(tx4))
        h34 = sha256_hash(h3 + h4)
        expected_root_4 = sha256_hash(h12 + h34)
        print(f"\n5. Merkle Root con 4 transacciones:\n   -> {root_4}")
        print("   -> Nivel 1 del recorrido:")
        print(f"      H12 = sha256(H1 + H2) = {h12}")
        print(f"      H34 = sha256(H3 + H4) = {h34}")
        print("   -> Nivel 2 del recorrido (raíz):")
        print(f"      root = sha256(H12 + H34) = {expected_root_4}")
        if root_4 != expected_root_4:
            raise AssertionError("Cálculo incorrecto para 4 hojas")

        print("\n[OK] ¡Todas las pruebas del Arbol de Merkle superadas con exito!")
        print("==================================================")
    except AssertionError as ae:
        print(f"[FALLO EN PRUEBAS] {ae}")
        raise
    except Exception as e:
        print(f"[ERROR] Ejecución de pruebas fallida: {e}")
        raise
