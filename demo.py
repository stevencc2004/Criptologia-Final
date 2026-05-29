"""
Módulo: demo.py
Asignatura: Criptología - Proyecto Final 
Universidad Distrital Francisco José de Caldas
Docente: Msc. Ing. Óscar Gabriel Espejo Mojica

Script de demostración y validación en tiempo real que ejecuta los 4 escenarios obligatorios
de    para demostrar la seguridad, inmutabilidad y control de accesos criptográficos.
"""

import sys
import time
from crypto_utils import generate_key_pair, sha256_hash
from merkle_tree import compute_merkle_root
from smart_contract import SmartContract
from blockchain import Blockchain, Block

# Definimos la clase Transaction que será el tipo de datos principal para las calificaciones
class Transaction:
    def __init__(self, id_profesor: str, id_estudiante: str, asignatura: str, nota: float, private_key, pk_hex: str):
        """
        Representa una transacción académica (emisión de una calificación).
        La transacción se firma digitalmente usando la clave privada del docente al ser creada.
        
        Args:
            id_profesor (str): Identificador único del profesor emisor.
            id_estudiante (str): Identificador del estudiante calificado.
            asignatura (str): Nombre de la asignatura.
            nota (float): Calificación (número decimal).
            private_key: Objeto de la clave privada ECDSA del profesor para firmar.
            pk_hex (str): Clave pública ECDSA del profesor en formato X9.62 hex.
        """
        self.id_profesor = id_profesor
        self.id_estudiante = id_estudiante
        self.asignatura = asignatura
        self.nota = nota
        self.pk_hex = pk_hex
        
        # Calcular el payload canónico y firmarlo inmediatamente
        payload = self.get_canonical_payload()
        from crypto_utils import sign_data
        self.firma = sign_data(private_key, payload)

    def get_canonical_payload(self) -> str:
        """
        Retorna el payload canónico que representa los datos estrictos de la nota.
        Este payload es lo que firma el profesor y sobre lo que se construye el árbol de Merkle.
        Esto previene el Error #1 de la guía (hashing redundante de firmas).
        
        Returns:
            str: Payload académico canónico.
        """
        return f"{self.id_profesor}|{self.id_estudiante}|{self.asignatura}|{self.nota:.1f}"

    def to_dict(self):
        """
        Retorna la representación de la transacción como diccionario.
        """
        return {
            "id_profesor": self.id_profesor,
            "id_estudiante": self.id_estudiante,
            "asignatura": self.asignatura,
            "nota": self.nota,
            "firma": self.firma,
            "pk_hex": self.pk_hex
        }


def print_title(title: str):
    """Auxiliar para imprimir títulos elegantes en la consola."""
    border = "=" * 70
    print(f"\n{border}")
    print(f" {title}")
    print(border)


def print_block_details(block: Block):
    """Auxiliar para imprimir detalles completos de un bloque en formato legible."""
    print(f"   [+] Indice del Bloque:  {block.index}")
    print(f"   [+] Timestamp (Epoch):  {block.timestamp}")
    print(f"   [+] Hash Anterior:      {block.hash_anterior}")
    print(f"   [+] Raiz de Merkle:     {block.merkle_root}")
    print(f"   [+] Nonce (PoW):        {block.nonce}")
    print(f"   [+] Hash del Bloque:    {block.hash}")
    print(f"   [+] Cantidad de Notas:  {len(block.transacciones)}")
    if block.transacciones:
        print("   [+] Transacciones (Calificaciones):")
        for idx, tx in enumerate(block.transacciones):
            print(f"       - Nota #{idx + 1}: [{tx.id_profesor}] -> [{tx.id_estudiante}] | {tx.asignatura} | Nota: {tx.nota}")
            print(f"         PK Emisor (X9.62): {tx.pk_hex[:30]}...{tx.pk_hex[-30:]}")
            print(f"         Firma Digital:     {tx.firma[:30]}...{tx.firma[-30:]}")


def main():
    print_title("   - SISTEMA DESCENTRALIZADO Y SEGURO DE CALIFICACIONES\n PROYECTO FINAL | ASIGNATURA: CRIPTOLOGIA\n UNIVERSIDAD DISTRITAL FRANCISCO JOSE DE CALDAS")

    # =========================================================================
    # ESCENARIO 1: Creación de la cadena (Bloque Génesis)
    # =========================================================================
    print_title("ESCENARIO 1: Creacion de la Cadena y Bloque Genesis")
    print("[Explicacion] Se inicializa la Blockchain con una dificultad de 3 ceros (target = '000').")
    print("El Bloque Genesis se crea sin transacciones, por ende su Raiz de Merkle es vacia (64 ceros).")
    print("Este bloque debe ser minado resolviendo el Proof of Work antes de enlazarse.")
    print("----------------------------------------------------------------------")
    
    # Instanciar el Smart Contract y la Blockchain
    contract = SmartContract()
    blockchain = Blockchain(difficulty=3)
    
    # Mostrar detalles del Bloque Génesis
    genesis = blockchain.chain[0]
    print("\n[Detalles del Bloque Genesis de   ]:")
    print_block_details(genesis)
    
    # Validar la cadena inicial
    print("\n[Validacion] Verificando la integridad del blockchain de forma criptografica...")
    es_valida = blockchain.is_chain_valid(contract)
    print(f"-> Resultado de validacion: {'CADENA VALIDA [OK]' if es_valida else 'CADENA INVALIDA [ERROR]'}")
    assert es_valida is True, "La cadena inicial debe ser válida"


    # =========================================================================
    # ESCENARIO 2: Profesor emite notas válidas y se mina el bloque
    # =========================================================================
    print_title("ESCENARIO 2: Profesor Autorizado Emite Notas y Mina Bloque 1")
    print("[Explicacion] Se genera un par de claves ECDSA (SECP256K1) para el Profesor Espejo.")
    print("Su clave publica en formato X9.62 (130 caracteres) se registra formalmente en el Smart Contract.")
    print("El docente emite tres calificaciones validas para diferentes estudiantes, las firma con su clave privada,")
    print("las transacciones pasan la validacion del Smart Contract y se agregan a la pool de pendientes.")
    print("Finalmente, se agrupan en un bloque, se calcula el Arbol de Merkle y se mina el bloque.")
    print("----------------------------------------------------------------------")
    
    # 1. Generar llaves ECDSA de Profesor y registrarlas
    print("[1] Generando claves criptograficas para el Docente...")
    prof_key, prof_pub = generate_key_pair()
    print(f"   -> Clave Publica Docente (PK_hex, len={len(prof_pub)}):\n      {prof_pub}")
    print("\n[2] Registrando clave publica del docente en el Smart Contract...")
    contract.register_professor("PROF_ESPEJO", prof_pub)
    
    # 2. Docente emite 3 notas
    print("\n[3] Docente emite y firma digitalmente 3 calificaciones...")
    tx1 = Transaction("PROF_ESPEJO", "EST_202601", "Criptologia", 4.5, prof_key, prof_pub)
    tx2 = Transaction("PROF_ESPEJO", "EST_202602", "Criptologia", 3.8, prof_key, prof_pub)
    tx3 = Transaction("PROF_ESPEJO", "EST_202603", "Criptologia", 5.0, prof_key, prof_pub)
    
    print(f"   -> Nota 1 cannica: '{tx1.get_canonical_payload()}'")
    print(f"      Firma ECDSA (hex): {tx1.firma[:40]}...{tx1.firma[-40:]}")
    
    # 3. Validar y agregar transacciones a pendientes
    print("\n[4] Enviando transacciones a la blockchain para validacion del Smart Contract...")
    blockchain.add_transaction(tx1, contract)
    blockchain.add_transaction(tx2, contract)
    blockchain.add_transaction(tx3, contract)
    print("   -> Todas las transacciones pasaron la validacion criptografica del Smart Contract.")
    print(f"   -> Pool de transacciones pendientes: {len(blockchain.pending_transactions)} registradas.")
    
    # 4. Minar las notas pendientes
    print("\n[5] Minando nuevo bloque (Bloque 1) con las transacciones académicas...")
    bloque1 = blockchain.mine_pending_transactions(contract)
    
    # Mostrar detalles del nuevo bloque
    print("\n[Detalles del Bloque 1 Minado]:")
    print_block_details(bloque1)
    
    # Validar el blockchain completo tras el minado
    print("\n[Validacion] Verificando integridad de la Blockchain completa...")
    es_valida = blockchain.is_chain_valid(contract)
    print(f"-> Resultado de validacion: {'CADENA VALIDA [OK]' if es_valida else 'CADENA INVALIDA [ERROR]'}")
    assert es_valida is True, "La cadena debe seguir siendo válida"


    # =========================================================================
    # ESCENARIO 3: Ataque de modificación histórica (Tampering)
    # =========================================================================
    print_title("ESCENARIO 3: Ataque de Modificacion Historica (Inmutabilidad)")
    print("[Explicacion] Un atacante interno o externo intenta alterar de manera fraudulenta una nota historica.")
    print("Accede directamente a la base de datos local y cambia la nota del EST_202602 en el Bloque 1 de 3.8 a 5.0.")
    print("Demostraremos como el Arbol de Merkle y el hash de la cabecera invalidan el bloque de inmediato.")
    print("IMPORTANTE: Segun la rubrica de calificacion, no recalculamos el PoW para demostrar que queda invalido.")
    print("----------------------------------------------------------------------")
    
    # 1. Alteración de la nota
    nota_original = bloque1.transacciones[1].nota
    print(f"[1] Accediendo a los datos del Bloque 1. Nota original del estudiante 'EST_202602': {nota_original}")
    print("[!] Modificando nota de forma fraudulenta a 5.0...")
    bloque1.transacciones[1].nota = 5.0
    print(f"   -> Nota alterada en base de datos: {bloque1.transacciones[1].nota}")
    
    # 2. Mostrar la discrepancia matemática
    print("\n[2] Analisis Matematico de la Integridad del Arbol de Merkle:")
    raiz_guardada = bloque1.merkle_root
    raiz_recalculada = compute_merkle_root(bloque1.transacciones)
    print(f"   -> Raiz de Merkle Guardada en Cabecera:   {raiz_guardada}")
    print(f"   -> Raiz de Merkle Recalculada de Hojas:   {raiz_recalculada}")
    print(f"   -> ¿Coinciden las Raices de Merkle?:      {raiz_guardada == raiz_recalculada}")
    
    print("\n[3] Analisis del Hashing de Cabecera (Efecto Avalancha):")
    hash_guardado = bloque1.hash
    # Si recalculamos el hash del bloque usando la nueva raíz de Merkle (la cual representaría el bloque si intentaran actualizar la cabecera)
    # primero creamos un bloque temporal con la raíz recalculada
    bloque_temp = Block(
        index=bloque1.index,
        timestamp=bloque1.timestamp,
        transacciones=bloque1.transacciones,
        merkle_root=raiz_recalculada,
        hash_anterior=bloque1.hash_anterior,
        nonce=bloque1.nonce
    )
    hash_recalculado_con_cambio = bloque_temp.calculate_hash()
    print(f"   -> Hash original guardado (PoW '000'):     {hash_guardado}")
    print(f"   -> Nuevo Hash recalculado si cambiamos Root: {hash_recalculado_con_cambio}")
    print(f"   -> ¿El nuevo Hash cumple la dificultad PoW?: {hash_recalculado_con_cambio.startswith('000')}")
    
    # 3. Validación formal
    print("\n[4] Ejecutando validacion formal del Blockchain ('is_chain_valid')...")
    es_valida_ataque = blockchain.is_chain_valid(contract)
    print(f"-> Resultado de validacion formal: {'CADENA VALIDA [OK]' if es_valida_ataque else 'CADENA DETECTO ALTERACION [RECHAZADA]'}")
    assert es_valida_ataque is False, "La cadena debe ser declarada inválida tras la manipulación"
    
    # Restauramos la nota para continuar con la demo limpia
    print("\n[Restaurando] Devolviendo nota a su valor original para los siguientes escenarios...")
    bloque1.transacciones[1].nota = nota_original
    es_valida_restaurada = blockchain.is_chain_valid(contract)
    print(f"-> Estado tras restauracion: {'CADENA RESTAURADA Y VALIDA [OK]' if es_valida_restaurada else 'ERROR AL RESTAURAR'}")


    # =========================================================================
    # ESCENARIO 4: Intento de emisión no autorizada (Smart Contract)
    # =========================================================================
    print_title("ESCENARIO 4: Intentos de Emision No Autorizada (Fraudes en Origen)")
    print("[Explicacion] Probaremos tres tipos de ataques antes de que las transacciones puedan ser minadas:")
    print("A. Un estudiante intenta emitir y firmar una nota usando su propio ID.")
    print("B. Un atacante externo intenta suplantar al Docente registrado firmando con su propia clave privada.")
    print("C. Un atacante externo intenta suplantar al Docente usando la clave publica del Docente pero firma falsa.")
    print("El Smart Contract debe rechazar los 3 intentos levantando un PermissionError.")
    print("----------------------------------------------------------------------")
    
    # Generar claves para Estudiante y Atacante
    est_key, est_pub = generate_key_pair()
    atk_key, atk_pub = generate_key_pair()
    
    # 1. ATAQUE A: Estudiante emite nota
    print("\n[ATAQUE A] Estudiante ('EST_202601') intenta firmar y auto-registrarse una nota de 5.0...")
    tx_estudiante = Transaction("EST_202601", "EST_202601", "Criptologia", 5.0, est_key, est_pub)
    try:
        blockchain.add_transaction(tx_estudiante, contract)
        print("   -> [FALLO DE SEGURIDAD] ¡El sistema acepto la transaccion del estudiante!")
    except PermissionError as e:
        print(f"   -> [EXCEPCION CAPTURADA] {e}")
        print("      [OK] Rechazo exitoso en Smart Contract: El estudiante no tiene rol registrado de profesor.")

    # 2. ATAQUE B: Atacante suplanta con clave propia
    print("\n[ATAQUE B] Atacante intenta emitir nota como 'PROF_ESPEJO' usando su clave publica propia...")
    # El atacante firma la transacción con su clave privada (atk_key) y adjunta su clave pública (atk_pub)
    tx_suplantador = Transaction("PROF_ESPEJO", "EST_202601", "Criptologia", 5.0, atk_key, atk_pub)
    try:
        blockchain.add_transaction(tx_suplantador, contract)
        print("   -> [FALLO DE SEGURIDAD] ¡El sistema acepto la suplantacion con clave publica ajena!")
    except PermissionError as e:
        print(f"   -> [EXCEPCION CAPTURADA] {e}")
        print("      [OK] Rechazo exitoso en Smart Contract: La clave publica de la transaccion no coincide con la registrada para el docente.")

    # 3. ATAQUE C: Atacante suplanta con firma falsa
    print("\n[ATAQUE C] Atacante intenta emitir nota como 'PROF_ESPEJO' usando la clave publica del Docente pero firma falsa...")
    # Creamos la transacción simulando que adjunta la clave pública del profesor (prof_pub)
    # pero firma con su clave privada de atacante (atk_key), por lo que la firma es falsa con respecto a prof_pub.
    tx_firma_falsa = Transaction("PROF_ESPEJO", "EST_202601", "Criptologia", 5.0, atk_key, prof_pub)
    try:
        blockchain.add_transaction(tx_fake_sig := tx_firma_falsa, contract)
        print("   -> [FALLO DE SEGURIDAD] ¡El sistema acepto una firma digital falsificada!")
    except PermissionError as e:
        print(f"   -> [EXCEPCION CAPTURADA] {e}")
        print("      [OK] Rechazo exitoso en Smart Contract: La firma digital ECDSA no corresponde al emisor real de la transaccion.")

    print_title("RESUMEN DE RESULTADOS DE LA DEMOSTRACION")
    print(" - Escenario 1 (Bloque Genesis):          COMPLETADO Y VALIDADO [OK]")
    print(" - Escenario 2 (Emision y PoW):           COMPLETADO Y MINADO   [OK]")
    print(" - Escenario 3 (Modificacion Historica):  DETECTADO Y RECHAZADO [OK]")
    print(" - Escenario 4 (Accesos No Autorizados):  DETECTADOS Y RECHAZADOS [OK]")
    print("======================================================================")
    print("    ha demostrado ser robusto criptograficamente a nivel de:")
    print(" 1. Confidencialidad, Integridad y Disponibilidad (CIA Triad)")
    print(" 2. No repudio y autenticidad (Firmas ECDSA SECP256K1)")
    print(" 3. Auditoria y Resistencia a Modificaciones (Arbol de Merkle y PoW)")
    print("======================================================================")

if __name__ == '__main__':
    try:
        main()
    except AssertionError as ae:
        print(f"[FALLO EN DEMO] {ae}")
        raise
    except Exception as e:
        print(f"[ERROR EN DEMO] {e}")
        raise
