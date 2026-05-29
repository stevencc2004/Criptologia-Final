"""
Módulo: blockchain.py
Asignatura: Criptología - Proyecto Final 
Universidad Distrital Francisco José de Caldas

Este módulo define las clases Block y Blockchain, estructurando la cabecera del bloque,
el cálculo canónico de hashes, el algoritmo de Proof of Work (Prueba de Trabajo)
y la lógica de verificación de integridad y consistencia de toda la cadena.
"""

import time
from crypto_utils import sha256_hash
from merkle_tree import compute_merkle_root

class Block:
    def __init__(self, index: int, timestamp: float, transacciones: list, merkle_root: str, hash_anterior: str, nonce: int = 0, hash_val: str = ""):
        """
        Inicializa un bloque de la cadena con sus cabeceras y transacciones.
        
        Args:
            index (int): Posición del bloque en la cadena (0 = Génesis).
            timestamp (float): Tiempo Unix de creación del bloque.
            transacciones (list): Lista de transacciones en el cuerpo del bloque.
            merkle_root (str): Raíz del árbol de Merkle calculada de las transacciones.
            hash_anterior (str): Hash SHA-256 del bloque precedente.
            nonce (int): Valor entero para cumplir el Proof of Work.
            hash_val (str, opcional): Hash precalculado o vacío para calcular en el init.
        """
        self.index = index
        self.timestamp = timestamp
        self.transacciones = transacciones
        self.merkle_root = merkle_root
        self.hash_anterior = hash_anterior
        self.nonce = nonce
        self.hash = hash_val if hash_val else self.calculate_hash()

    def calculate_hash(self) -> str:
        """
        Calcula el hash SHA-256 de la cabecera del bloque.
        
        Returns:
            str: Hash hexadecimal resultante de 64 caracteres.
        """
        # Formateamos los campos de forma determinista para evitar fallos de precisión float
        header_str = f"{self.index}|{self.timestamp:.6f}|{self.merkle_root}|{self.hash_anterior}|{self.nonce}"
        return sha256_hash(header_str)

    def to_dict(self):
        """
        Retorna una representación en diccionario del bloque para facilitar su visualización.
        """
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "hash_anterior": self.hash_anterior,
            "nonce": self.nonce,
            "hash": self.hash,
            "transacciones": [tx.to_dict() if hasattr(tx, 'to_dict') else tx for tx in self.transacciones]
        }


class Blockchain:
    def __init__(self, difficulty: int = 3):
        """
        Inicializa una nueva Blockchain con una dificultad específica de minado y
        crea de forma automática el Bloque Génesis minado.
        
        Args:
            difficulty (int): Número de ceros iniciales requeridos en el hash.
        """
        # Validar dificultad provista
        if not isinstance(difficulty, int) or difficulty < 0:
            raise ValueError("La dificultad debe ser un entero no negativo")
        self.difficulty = difficulty
        self.chain = []
        self.pending_transactions = []
        
        # Crear y minar automáticamente el bloque Génesis
        self.create_genesis_block()

    def create_genesis_block(self):
        """
        Crea, mina y añade a la cadena el bloque Génesis (Bloque 0).
        """
        timestamp = 1700000000.0  # Timestamp fijo para reproducibilidad o time.time()
        # Usamos time.time() pero controlado
        timestamp = time.time()
        
        # Génesis no tiene transacciones, su merkle root es 64 ceros.
        merkle_root = "0" * 64
        hash_anterior = "0" * 64
        
        genesis_block = Block(
            index=0,
            timestamp=timestamp,
            transacciones=[],
            merkle_root=merkle_root,
            hash_anterior=hash_anterior,
            nonce=0
        )
        
        print("[Blockchain] Creando Bloque Genesis...")
        self.mine_block(genesis_block)
        self.chain.append(genesis_block)

    def mine_block(self, block: Block):
        """
        Algoritmo Proof of Work (PoW).
        
        Imprime los resultados de intentos y tiempos en consola de forma descriptiva.
        
        Args:
            block (Block): Bloque a minar.
        """
        # Validaciones iniciales
        if not isinstance(block, Block):
            raise TypeError("El objeto a minar debe ser una instancia de Block")

        start_time = time.time()
        attempts = 0
        target = "0" * self.difficulty
        # Asegurar nonce inicial
        if not isinstance(block.nonce, int) or block.nonce < 0:
            block.nonce = 0

        # Seguridad: límite razonable de intentos para evitar loops infinitos en entornos de prueba
        MAX_ATTEMPTS = 10_000_000

        while True:
            # Validar formatos críticos antes de calcular
            if not isinstance(block.merkle_root, str) or len(block.merkle_root) != 64:
                raise ValueError(f"Merkle root inválida en bloque {block.index}")
            if not isinstance(block.hash_anterior, str) or len(block.hash_anterior) != 64:
                raise ValueError(f"Hash anterior inválido en bloque {block.index}")

            hash_val = block.calculate_hash()
            attempts += 1
            if hash_val.startswith(target):
                block.hash = hash_val
                duration = time.time() - start_time
                print(f"[Minado PoW] ¡Bloque {block.index} minado exitosamente!")
                print(f"   -> Nonce Encontrado: {block.nonce}")
                print(f"   -> Hash del Bloque:  {block.hash}")
                print(f"   -> Total Intentos:  {attempts}")
                print(f"   -> Tiempo Minado:   {duration:.4f} segundos")
                break

            if attempts >= MAX_ATTEMPTS:
                raise RuntimeError(f"Minado abortado tras {MAX_ATTEMPTS} intentos en bloque {block.index}")

            block.nonce += 1

    def add_transaction(self, transaction, contract) -> bool:
        """
        Valida una transacción contra las reglas de seguridad de un Smart Contract.
        Si es válida, la añade a la lista de transacciones pendientes.
        
        Args:
            transaction: Objeto de transacción.
            contract: Instancia del SmartContract para validación.
            
        Returns:
            bool: True si la transacción fue añadida.
        """
        # Comprobaciones básicas de tipo y estructura
        if transaction is None:
            raise ValueError("Transacción vacía no permitida")
        if contract is None or not hasattr(contract, 'validate_transaction'):
            raise ValueError("Se requiere un Smart Contract válido con 'validate_transaction()'")

        # Validar estructura mínima de la transacción
        if not hasattr(transaction, 'get_canonical_payload'):
            raise AttributeError("La transacción debe implementar 'get_canonical_payload()'")
        if not hasattr(transaction, 'firma') or not isinstance(transaction.firma, str) or len(transaction.firma) == 0:
            raise ValueError("La transacción debe incluir una firma ECDSA válida en formato hexadecimal")
        if not hasattr(transaction, 'pk_hex') or not isinstance(transaction.pk_hex, str):
            raise ValueError("La transacción debe incluir 'pk_hex' con la clave pública del emisor")

        payload = transaction.get_canonical_payload()
        if not isinstance(payload, str) or len(payload.strip()) == 0:
            raise ValueError("El payload canónico de la transacción no puede estar vacío")

        # Validar en el Smart Contract antes de agregar al pool
        try:
            contract.validate_transaction(transaction)
        except PermissionError:
            # Re-lanzar PermissionError para que el llamador lo gestione explícitamente
            raise
        except Exception as e:
            # Cualquier otra excepción se trata como error de validación
            raise ValueError(f"Transacción inválida: {e}")

        # Si todo pasó, añadir al pool
        self.pending_transactions.append(transaction)
        return True

    def mine_pending_transactions(self, contract) -> Block:
        """
        Agrupa todas las transacciones pendientes en un nuevo bloque, calcula el
        Merkle Root, enlaza con el bloque previo, ejecuta el PoW y añade el bloque
        a la blockchain.
        
        Returns:
            Block: El bloque recién minado y añadido a la cadena.
        """
        if not self.pending_transactions:
            raise ValueError("[Blockchain] No hay transacciones pendientes para minar.")

        # Validar que se proporcionó un Smart Contract válido para re-verificar firmas
        if contract is None or not hasattr(contract, 'validate_transaction'):
            raise ValueError("Se requiere una instancia válida de SmartContract para minar transacciones")

        if not self.chain:
            raise RuntimeError("La cadena no contiene bloques previos. Cree el genesis antes de minar.")

        last_block = self.chain[-1]

        # Validar y filtrar transacciones pendientes mediante el Smart Contract
        valid_txs = []
        for tx in list(self.pending_transactions):
            try:
                # Validaciones de estructura local antes de delegar al Smart Contract
                if tx is None:
                    raise ValueError("Transacción vacía encontrada en pool pendientes")
                if not hasattr(tx, 'get_canonical_payload') or not hasattr(tx, 'firma') or not hasattr(tx, 'pk_hex'):
                    raise ValueError("Transacción no cumple la estructura mínima requerida (payload/firma/pk_hex)")

                contract.validate_transaction(tx)
                valid_txs.append(tx)
            except PermissionError as e:
                print(f"[WARN] Transacción descartada por validación (permiso): {e}")
            except Exception as e:
                print(f"[WARN] Transacción descartada por validación: {e}")

        if not valid_txs:
            raise ValueError("Ninguna transacción pendiente pasó la validación del Smart Contract.")

        # Calcular la raíz de Merkle de las transacciones válidas
        merkle_root = compute_merkle_root(valid_txs)
        
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transacciones=list(valid_txs),
            merkle_root=merkle_root,
            hash_anterior=last_block.hash,
            nonce=0
        )
        
        # Minar el bloque
        self.mine_block(new_block)
        
        # Añadir a la cadena y limpiar pendientes (eliminamos solo las válidas minadas)
        self.chain.append(new_block)
        # Eliminar las transacciones válidas del pool pendiente
        remaining = [tx for tx in self.pending_transactions if tx not in valid_txs]
        self.pending_transactions = remaining
        
        return new_block

    def is_chain_valid(self, contract) -> bool:
        """
        Verifica la validez de toda la blockchain:
        1. Validez de los hashes de los bloques (Proof of Work e integridad de cabecera).
        2. Enlace correcto entre bloques (punteros hash_anterior).
        3. Consistencia del Arbol de Merkle (recalcula la raiz y compara con la cabecera).
        4. Autenticidad de las transacciones (valida cada firma en el Smart Contract).
        
        Args:
            contract: Instancia del SmartContract para validación de firmas.
            
        Returns:
            bool: True si la cadena es 100% íntegra y válida.
        """
        target = "0" * self.difficulty

        if not isinstance(contract, object) or not hasattr(contract, 'validate_transaction'):
            raise ValueError("Se requiere un Smart Contract válido para verificar la cadena")

        if not self.chain:
            print("[ERROR] La cadena está vacía")
            return False

        # Validar bloque Génesis explícitamente
        genesis = self.chain[0]
        if genesis.index != 0:
            print("[ERROR GENESIS] El primer bloque debe tener index 0")
            return False
        if genesis.merkle_root != "0" * 64:
            print("[ERROR GENESIS] Merkle root del genesis inválida")
            return False
        if genesis.hash_anterior != "0" * 64:
            print("[ERROR GENESIS] Hash anterior del genesis inválido")
            return False
        if genesis.hash != genesis.calculate_hash():
            print("[ERROR GENESIS] Hash del genesis inconsistente")
            return False
        if not genesis.hash.startswith(target):
            print("[ERROR GENESIS] Genesis no cumple la dificultad PoW")
            return False

        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]

            # Validaciones estructurales básicas
            if not isinstance(current.index, int) or current.index != i:
                print(f"[ERROR ESTRUCTURA] Índice inválido en bloque {i}")
                return False

            recalculated_hash = current.calculate_hash()
            if current.hash != recalculated_hash:
                print(f"[ERROR INTEGRIDAD] Bloque {current.index} tiene un Hash inconsistente.")
                print(f"   -> Almacenado:   {current.hash}")
                print(f"   -> Recalculado: {recalculated_hash}")
                return False

            if not current.hash.startswith(target):
                print(f"[ERROR CONSENSO] Bloque {current.index} no cumple con la dificultad de Proof of Work '{target}'.")
                return False

            if current.hash_anterior != prev.hash:
                print(f"[ERROR ENLACE] Bloque {current.index} apunta a un hash anterior incorrecto.")
                print(f"   -> Apunta a:      {current.hash_anterior}")
                print(f"   -> Hash de prev:  {prev.hash}")
                return False

            computed_root = compute_merkle_root(current.transacciones)
            if current.merkle_root != computed_root:
                print(f"[ERROR MERKLE] Bloque {current.index} tiene una raiz de Merkle inconsistente.")
                print(f"   -> En cabecera:   {current.merkle_root}")
                print(f"   -> Recalculada:   {computed_root}")
                return False

            for tx_idx, tx in enumerate(current.transacciones):
                try:
                    # Aceptamos que contract.validate_transaction puede lanzar distintos errores
                    contract.validate_transaction(tx)
                except Exception as e:
                    print(f"[ERROR FRAUDE] Bloque {current.index}, Transaccion #{tx_idx} invalida: {e}")
                    return False

        return True

# Bloque de prueba de funcionamiento autónomo
if __name__ == '__main__':
    print("==================================================")
    print("PRUEBA UNITARIA: blockchain.py")
    print("==================================================")
    
    # Importamos herramientas necesarias para el test
    from smart_contract import SmartContract
    from crypto_utils import generate_key_pair, sign_data

    # Mock clase Transacción
    class TestTransaction:
        def __init__(self, id_profesor, id_estudiante, asignatura, nota, private_key, pk_hex):
            self.id_profesor = id_profesor
            self.id_estudiante = id_estudiante
            self.asignatura = asignatura
            self.nota = nota
            self.pk_hex = pk_hex
            self.firma = sign_data(private_key, self.get_canonical_payload())

        def get_canonical_payload(self) -> str:
            return f"{self.id_profesor}|{self.id_estudiante}|{self.asignatura}|{self.nota}"

        def to_dict(self):
            return {
                "id_profesor": self.id_profesor,
                "id_estudiante": self.id_estudiante,
                "asignatura": self.asignatura,
                "nota": self.nota,
                "firma": self.firma,
                "pk_hex": self.pk_hex
            }

    # 1. Instanciamos blockchain y Smart Contract
    bc = Blockchain(difficulty=3)
    contract = SmartContract()
    
    # 2. Registramos un profesor
    prof_key, prof_pub = generate_key_pair()
    contract.register_professor("PROF_OSCAR", prof_pub)
    
    # 3. Validar cadena inicial (sola la génesis)
    print("\nVerificando validez de cadena inicial (solo genesis)...")
    es_valida = bc.is_chain_valid(contract)
    print(f"-> ¿Cadena valida?: {es_valida}")
    assert es_valida is True
    
    # 4. Crear transacciones válidas y agregarlas
    print("\nEmitiendo transacciones legitimas...")
    tx1 = TestTransaction("PROF_OSCAR", "EST_001", "Criptologia", 4.8, prof_key, prof_pub)
    tx2 = TestTransaction("PROF_OSCAR", "EST_002", "Criptologia", 3.5, prof_key, prof_pub)
    
    bc.add_transaction(tx1, contract)
    bc.add_transaction(tx2, contract)
    print("[OK] Transacciones agregadas al pool de pendientes.")
    
    # 5. Minar las transacciones pendientes en el Bloque 1
    print("\nMinando Bloque 1...")
    bloque1 = bc.mine_pending_transactions(contract)
    
    # 6. Validar la cadena con el nuevo bloque
    print("\nVerificando validez de cadena despues del minado...")
    es_valida = bc.is_chain_valid(contract)
    print(f"-> ¿Cadena valida?: {es_valida}")
    assert es_valida is True
    
    # 7. Intento de fraude: Manipular una nota histórica del Bloque 1
    print("\n--- Simulación de ataque: Manipulando nota en Bloque 1 ---")
    print(f"Original Nota de EST_002: {bloque1.transacciones[1].nota}")
    # Alteramos la nota directamente
    bloque1.transacciones[1].nota = 5.0
    print(f"Alterada Nota de EST_002: {bloque1.transacciones[1].nota}")
    
    # Validamos integridad
    print("\nVerificando validez de cadena tras ataque...")
    es_valida_tampered = bc.is_chain_valid(contract)
    print(f"-> ¿Cadena valida despues del ataque?: {es_valida_tampered}")
    assert es_valida_tampered is False, "La blockchain debería detectar el ataque y declararse inválida"
    print("[OK] ¡El ataque fue detectado con exito y la cadena fue invalidada!")
    
    print("\n[OK] ¡Todas las pruebas de Blockchain superadas con exito!")
    print("==================================================")
