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
        start_time = time.time()
        attempts = 0
        target = "0" * self.difficulty
        block.nonce = 0
        
        while True:
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
        # Validar en el Smart Contract antes de agregar al pool
        contract.validate_transaction(transaction)
        self.pending_transactions.append(transaction)
        return True

    def mine_pending_transactions(self) -> Block:
        """
        Agrupa todas las transacciones pendientes en un nuevo bloque, calcula el
        Merkle Root, enlaza con el bloque previo, ejecuta el PoW y añade el bloque
        a la blockchain.
        
        Returns:
            Block: El bloque recién minado y añadido a la cadena.
        """
        if not self.pending_transactions:
            raise ValueError("[Blockchain] No hay transacciones pendientes para minar.")
            
        last_block = self.chain[-1]
        
        # Calcular la raíz de Merkle de las transacciones pendientes
        merkle_root = compute_merkle_root(self.pending_transactions)
        
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transacciones=list(self.pending_transactions),
            merkle_root=merkle_root,
            hash_anterior=last_block.hash,
            nonce=0
        )
        
        # Minar el bloque
        self.mine_block(new_block)
        
        # Añadir a la cadena y limpiar pendientes
        self.chain.append(new_block)
        self.pending_transactions = []
        
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
        
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]
            
            # A. Verificar consistencia del hash almacenado con el recalculado de cabecera
            if current.hash != current.calculate_hash():
                print(f"[ERROR INTEGRIDAD] Bloque {current.index} tiene un Hash inconsistente.")
                print(f"   -> Almacenado:   {current.hash}")
                print(f"   -> Recalculado: {current.calculate_hash()}")
                return False
                
            # B. Verificar que cumpla la dificultad Proof of Work
            if not current.hash.startswith(target):
                print(f"[ERROR CONSENSO] Bloque {current.index} no cumple con la dificultad de Proof of Work '{target}'.")
                return False
                
            # C. Verificar el enlace de hash con el bloque anterior
            if current.hash_anterior != prev.hash:
                print(f"[ERROR ENLACE] Bloque {current.index} apunta a un hash anterior incorrecto.")
                print(f"   -> Apunta a:      {current.hash_anterior}")
                print(f"   -> Hash de prev:  {prev.hash}")
                return False
                
            # D. Verificar la raíz de Merkle recalculada sobre las transacciones del cuerpo
            computed_root = compute_merkle_root(current.transacciones)
            if current.merkle_root != computed_root:
                print(f"[ERROR MERKLE] Bloque {current.index} tiene una raiz de Merkle inconsistente.")
                print(f"   -> En cabecera:   {current.merkle_root}")
                print(f"   -> Recalculada:   {computed_root}")
                return False
                
            # E. Verificar criptográficamente cada transacción en el bloque usando el Smart Contract
            for tx_idx, tx in enumerate(current.transacciones):
                try:
                    contract.validate_transaction(tx)
                except PermissionError as e:
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
    bloque1 = bc.mine_pending_transactions()
    
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
    assert es_valida_tampered is True, "La blockchain debería detectar el ataque y declararse inválida"
    print("[OK] ¡El ataque fue detectado con exito y la cadena fue invalidada!")
    
    print("\n[OK] ¡Todas las pruebas de Blockchain superadas con exito!")
    print("==================================================")
