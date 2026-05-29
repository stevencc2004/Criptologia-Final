"""
Módulo: demo.py
Asignatura: Criptología - Proyecto Final (EduChain)
Universidad Distrital Francisco José de Caldas
Docente: Msc. Ing. Óscar Gabriel Espejo Mojica

Script de demostración y validación en tiempo real que ejecuta los 4 escenarios obligatorios
de EduChain para demostrar la seguridad, inmutabilidad y control de accesos criptográficos.

VERSIÓN VERBOSE: Incluye explicaciones paso a paso de cada operación criptográfica.
"""

import sys
import time
from crypto_utils import generate_key_pair, sha256_hash, sign_data, verify_signature
from merkle_tree import compute_merkle_root, get_payload_from_tx
from smart_contract import SmartContract
from blockchain import Blockchain, Block


# ============================================================
# Clase principal de transacción académica
# ============================================================
class Transaction:
    def __init__(self, id_profesor: str, id_estudiante: str, asignatura: str, nota: float, private_key, pk_hex: str):
        """
        Representa una transacción académica (emisión de una calificación).
        La transacción se firma digitalmente usando la clave privada del docente al ser creada.
        """
        self.id_profesor = id_profesor
        self.id_estudiante = id_estudiante
        self.asignatura = asignatura
        self.nota = nota
        self.pk_hex = pk_hex
        payload = self.get_canonical_payload()
        self.firma = sign_data(private_key, payload)

    def get_canonical_payload(self) -> str:
        return f"{self.id_profesor}|{self.id_estudiante}|{self.asignatura}|{self.nota:.1f}"

    def to_dict(self):
        return {
            "id_profesor": self.id_profesor,
            "id_estudiante": self.id_estudiante,
            "asignatura": self.asignatura,
            "nota": self.nota,
            "firma": self.firma,
            "pk_hex": self.pk_hex
        }


# ============================================================
# Helpers de presentación en consola
# ============================================================
def separador(nivel=1):
    """Imprime un separador visual según el nivel de jerarquía."""
    if nivel == 1:
        print("\n" + "=" * 70)
    elif nivel == 2:
        print("  " + "-" * 66)
    else:
        print("  " + "·" * 66)

def print_title(title: str):
    """Imprime un título de escenario principal."""
    separador(1)
    for linea in title.strip().split("\n"):
        print(f"  {linea}")
    separador(1)

def print_step(numero: int, descripcion: str):
    """Imprime un paso numerado dentro de un escenario."""
    print(f"\n  [PASO {numero}] {descripcion}")
    print("  " + "·" * 50)

def print_concepto(etiqueta: str, valor: str, indent: int = 4):
    """Imprime un par clave-valor con indentación."""
    espacio = " " * indent
    print(f"{espacio}► {etiqueta}:")
    print(f"{espacio}  {valor}")

def print_ok(mensaje: str):
    print(f"  [✓ OK] {mensaje}")

def print_warn(mensaje: str):
    print(f"  [⚠ ATAQUE] {mensaje}")

def print_error(mensaje: str):
    print(f"  [✗ RECHAZADO] {mensaje}")

def esperar(segundos: float = 0.3):
    """Pausa breve para dar tiempo de lectura entre pasos."""
    time.sleep(segundos)

def mostrar_cabecera_bloque(block: Block, titulo: str = "Cabecera del Bloque"):
    """Muestra los campos de la cabecera de un bloque de forma detallada."""
    print(f"\n  ┌─ {titulo} ─────────────────────────────────────────")
    print(f"  │  Índice:          {block.index}")
    print(f"  │  Timestamp:       {block.timestamp:.6f}  (Unix epoch)")
    print(f"  │  Hash Anterior:   {block.hash_anterior[:32]}...")
    print(f"  │                   ...{block.hash_anterior[-32:]}")
    print(f"  │  Raíz de Merkle:  {block.merkle_root[:32]}...")
    print(f"  │                   ...{block.merkle_root[-32:]}")
    print(f"  │  Nonce (PoW):     {block.nonce}")
    print(f"  │  Hash del Bloque: {block.hash[:32]}...")
    print(f"  │                   ...{block.hash[-32:]}")
    print(f"  │  Nº Transac.:     {len(block.transacciones)}")
    print(f"  └──────────────────────────────────────────────────────")

def mostrar_transaccion(tx: Transaction, numero: int):
    """Muestra los campos de una transacción en detalle."""
    payload = tx.get_canonical_payload()
    hash_hoja = sha256_hash(payload)
    print(f"\n  ┌─ Transacción #{numero} ────────────────────────────────────")
    print(f"  │  Emisor (Profesor):  {tx.id_profesor}")
    print(f"  │  Receptor (Alum.):  {tx.id_estudiante}")
    print(f"  │  Asignatura:        {tx.asignatura}")
    print(f"  │  Nota:              {tx.nota}")
    print(f"  │  Payload Canónico:  {payload}")
    print(f"  │  Hash (hoja Merk.): {hash_hoja}")
    print(f"  │  Firma ECDSA (hex): {tx.firma[:32]}...")
    print(f"  │                     ...{tx.firma[-32:]}")
    print(f"  │  PK Emisor (X9.62): {tx.pk_hex[:32]}...")
    print(f"  │                     ...{tx.pk_hex[-32:]}")
    print(f"  └──────────────────────────────────────────────────────")


# ============================================================
# MAIN: Demostración por escenarios
# ============================================================
def main():
    print_title(
        "EDUCHAIN — SISTEMA DESCENTRALIZADO Y SEGURO DE CALIFICACIONES\n"
        "  Proyecto Final | Asignatura: Criptología\n"
        "  Universidad Distrital Francisco José de Caldas\n"
        "  Docente: Msc. Ing. Óscar Gabriel Espejo Mojica"
    )
    print("""
  EduChain demuestra que es matemáticamente imposible alterar una
  calificación histórica almacenada en la cadena sin que el sistema
  lo detecte de forma inmediata.

  Pilares criptográficos demostrados:
    1. SHA-256 (Hashing de cabecera con efecto avalancha)
    2. Árbol de Merkle (Integridad de transacciones)
    3. ECDSA SECP256K1 (Firmas digitales de docentes)
    4. Proof of Work (Consenso y dificultad de minado)
    5. Smart Contract (Control de acceso en origen)
    """)
    esperar(0.5)

    # =========================================================================
    # ESCENARIO 1: Bloque Génesis
    # =========================================================================
    print_title("ESCENARIO 1 — Creación de la Cadena y Bloque Génesis")
    print("""
  El Bloque Génesis (índice 0) es el primer bloque de la cadena.
  Es especial porque no tiene bloque anterior, por lo que su campo
  'hash_anterior' se inicializa con 64 ceros (valor nulo canónico).
  Tampoco contiene transacciones, así que su Raíz de Merkle también
  es 64 ceros por convención.

  A pesar de esto, el Bloque Génesis DEBE ser minado: hay que encontrar
  un nonce tal que SHA-256(cabecera) empiece con '000' (dificultad=3).
    """)
    esperar(0.3)

    print_step(1, "Instanciar el Smart Contract y la Blockchain")
    print("    El Smart Contract se inicializa con un registro de profesores vacío.")
    print("    La Blockchain se configura con dificultad = 3 (target = '000...').")
    print("    Al instanciar Blockchain, se dispara automáticamente la creación del Génesis.\n")
    esperar(0.2)

    contract = SmartContract()
    blockchain = Blockchain(difficulty=3)
    genesis = blockchain.chain[0]
    esperar(0.2)

    print_step(2, "Inspeccionar la cabecera del Bloque Génesis")
    print("    Verifiquemos cada campo y por qué tiene ese valor:\n")
    print(f"    • index = 0          → es el primer bloque (posición 0)")
    print(f"    • hash_anterior = {'0'*20}... → no hay bloque previo, se usa el valor nulo")
    print(f"    • merkle_root   = {'0'*20}... → sin transacciones, raíz nula por convención")
    print(f"    • nonce         = {genesis.nonce}         → valor encontrado para cumplir el PoW")
    print(f"    • hash          = {genesis.hash[:40]}...")
    print(f"      ¿Empieza con '000'? → {'SÍ ✓' if genesis.hash.startswith('000') else 'NO ✗'}")
    mostrar_cabecera_bloque(genesis, "Cabecera del Bloque Génesis")
    esperar(0.3)

    print_step(3, "Verificar la integridad criptográfica de la cadena inicial")
    print("    is_chain_valid() comprueba: hashes, enlaces, Merkle y firmas.\n")
    es_valida = blockchain.is_chain_valid(contract)
    print(f"\n    Resultado: {'CADENA VÁLIDA [✓]' if es_valida else 'CADENA INVÁLIDA [✗]'}")
    assert es_valida is True
    print_ok("Escenario 1 completado — Bloque Génesis minado y cadena válida.")
    esperar(0.5)


    # =========================================================================
    # ESCENARIO 2: Profesor emite notas y se mina el Bloque 1
    # =========================================================================
    print_title("ESCENARIO 2 — Docente Autorizado Emite Notas y Mina el Bloque 1")
    print("""
  En este escenario, el Docente 'PROF_ESPEJO' emitirá 3 calificaciones.
  El flujo completo es:
    a) Generar par de claves ECDSA (SECP256K1) para el docente.
    b) Registrar la clave pública en el Smart Contract.
    c) Construir cada transacción con su payload canónico y firma digital.
    d) El Smart Contract valida cada transacción antes de admitirla al pool.
    e) Calcular la Raíz del Árbol de Merkle de las 3 transacciones.
    f) Ejecutar Proof of Work para encontrar el nonce del Bloque 1.
    g) Enlazar el Bloque 1 al Génesis mediante el campo 'hash_anterior'.
    """)
    esperar(0.3)

    print_step(1, "Generar el par de claves ECDSA para el Docente")
    print("    Curva: SECP256K1 (la misma que usa Bitcoin y Ethereum).")
    print("    La clave pública se serializa en formato X9.62 no comprimido:")
    print("    prefijo '04' + coordenada X (32 bytes) + coordenada Y (32 bytes) = 65 bytes = 130 hex.\n")
    prof_key, prof_pub = generate_key_pair()
    print(f"    Clave Pública (130 hex chars, prefijo '04'):")
    print(f"      {prof_pub[:65]}")
    print(f"      {prof_pub[65:]}")
    print(f"    ¿Empieza con '04'? → {'SÍ ✓' if prof_pub.startswith('04') else 'NO ✗'}")
    print(f"    ¿Longitud 130?     → {'SÍ ✓' if len(prof_pub) == 130 else 'NO ✗'}")
    esperar(0.3)

    print_step(2, "Registrar la clave pública en el Smart Contract")
    print("    El Smart Contract almacena el mapeo: ID_Profesor → PK_hex.")
    print("    Solo los ID registrados aquí podrán emitir transacciones válidas.\n")
    contract.register_professor("PROF_ESPEJO", prof_pub)
    print(f"\n    Registro actual del Smart Contract: {{'PROF_ESPEJO': '{prof_pub[:20]}...'}}")
    esperar(0.3)

    print_step(3, "El Docente emite y firma 3 calificaciones")
    print("    Para cada nota, se construye el payload canónico:")
    print("    Formato: 'ID_Profesor|ID_Estudiante|Asignatura|Nota'")
    print("    Luego se firma con ECDSA(SHA-256) usando la clave privada del docente.\n")
    tx1 = Transaction("PROF_ESPEJO", "EST_202601", "Criptologia", 4.5, prof_key, prof_pub)
    tx2 = Transaction("PROF_ESPEJO", "EST_202602", "Criptologia", 3.8, prof_key, prof_pub)
    tx3 = Transaction("PROF_ESPEJO", "EST_202603", "Criptologia", 4.9, prof_key, prof_pub)
    mostrar_transaccion(tx1, 1)
    mostrar_transaccion(tx2, 2)
    mostrar_transaccion(tx3, 3)
    esperar(0.3)

    print_step(4, "Verificación individual de cada firma (pre-validación interna)")
    print("    Antes de enviar al Smart Contract, demostramos manualmente")
    print("    que verify_signature() comprueba correctamente cada firma:\n")
    for idx, tx in enumerate([tx1, tx2, tx3], 1):
        payload = tx.get_canonical_payload()
        es_firma_valida = verify_signature(tx.pk_hex, payload, tx.firma)
        print(f"    Transacción #{idx} → payload='{payload}'")
        print(f"      verify_signature() → {es_firma_valida} {'✓' if es_firma_valida else '✗'}")
    esperar(0.3)

    print_step(5, "Enviar transacciones al pool del Smart Contract")
    print("    add_transaction() invoca validate_transaction() del Smart Contract.")
    print("    Se comprueban 3 reglas en cadena:\n")
    print("      Regla 1: ¿Está registrado el ID del profesor?")
    print("      Regla 2: ¿Coincide la PK_hex con la registrada para ese ID?")
    print("      Regla 3: ¿Es válida la firma ECDSA sobre el payload canónico?\n")
    blockchain.add_transaction(tx1, contract)
    blockchain.add_transaction(tx2, contract)
    blockchain.add_transaction(tx3, contract)
    print(f"\n    Pool de transacciones pendientes: {len(blockchain.pending_transactions)} transaccion(es).")
    esperar(0.3)

    print_step(6, "Calcular la Raíz del Árbol de Merkle (antes del minado)")
    print("    El árbol de Merkle resume las 3 transacciones en un único hash de 256 bits.")
    print("    Con 3 hojas (impar), se duplica la última hoja para equilibrar el árbol:\n")
    h1 = sha256_hash(tx1.get_canonical_payload())
    h2 = sha256_hash(tx2.get_canonical_payload())
    h3 = sha256_hash(tx3.get_canonical_payload())
    h12 = sha256_hash(h1 + h2)
    h33 = sha256_hash(h3 + h3)
    raiz_merkle = sha256_hash(h12 + h33)
    print(f"    Hoja 1 (TX1): {h1[:40]}...")
    print(f"    Hoja 2 (TX2): {h2[:40]}...")
    print(f"    Hoja 3 (TX3): {h3[:40]}...")
    print(f"    Nivel 1:")
    print(f"      Nodo H(H1+H2): {h12[:40]}...")
    print(f"      Nodo H(H3+H3): {h33[:40]}...  ← H3 duplicado (impar)")
    print(f"    Raíz Merkle:   {raiz_merkle[:40]}...")
    merkle_calculado = compute_merkle_root(blockchain.pending_transactions)
    print(f"\n    Verificación: compute_merkle_root() = {merkle_calculado[:40]}...")
    print(f"    ¿Coincide con cálculo manual? → {'SÍ ✓' if raiz_merkle == merkle_calculado else 'NO ✗'}")
    esperar(0.3)

    print_step(7, "Minar el Bloque 1 (Proof of Work)")
    print("    El PoW itera el nonce desde 0 hasta encontrar un hash de cabecera")
    print("    que comience con '000'. Esto demuestra gasto computacional real.\n")
    print("    Formato de la cadena hasheada:")
    print("      'index|timestamp|merkle_root|hash_anterior|nonce'\n")
    bloque1 = blockchain.mine_pending_transactions()
    esperar(0.2)

    print_step(8, "Inspeccionar el Bloque 1 minado y su enlace con el Génesis")
    print("    Observemos cómo el 'hash_anterior' del Bloque 1 == 'hash' del Génesis:\n")
    print(f"    Hash del Génesis:         {genesis.hash}")
    print(f"    hash_anterior del Bloque1: {bloque1.hash_anterior}")
    print(f"    ¿Son iguales? → {'SÍ ✓ (enlace válido)' if genesis.hash == bloque1.hash_anterior else 'NO ✗'}")
    mostrar_cabecera_bloque(bloque1, "Cabecera del Bloque 1")
    esperar(0.3)

    print_step(9, "Verificar integridad completa de la cadena (Génesis + Bloque 1)")
    es_valida = blockchain.is_chain_valid(contract)
    print(f"\n    Resultado: {'CADENA VÁLIDA [✓]' if es_valida else 'CADENA INVÁLIDA [✗]'}")
    assert es_valida is True
    print_ok("Escenario 2 completado — 3 notas emitidas, firmadas, validadas y minadas.")
    esperar(0.5)


    # =========================================================================
    # ESCENARIO 3: Ataque de modificación histórica (Tampering)
    # =========================================================================
    print_title("ESCENARIO 3 — Ataque de Modificación Histórica (Tampering)")
    print("""
  Un atacante accede directamente a la base de datos local y cambia
  la nota de EST_202602 en el Bloque 1 de 3.8 → 5.0.

  EduChain debe detectar la alteración en 3 niveles independientes:
    Nivel 1: La Raíz de Merkle recalculada difiere de la cabecera.
    Nivel 2: Si se intenta actualizar la raíz en la cabecera, el hash
             del bloque cambia y deja de cumplir la dificultad PoW.
    Nivel 3: La firma ECDSA de la transacción alterada ya no es válida.
    """)
    esperar(0.3)

    nota_original = bloque1.transacciones[1].nota

    print_step(1, "Modificar la nota directamente en memoria (simula ataque DB)")
    print(f"    Nota original de EST_202602 en el Bloque 1: {nota_original}")
    print_warn("Alterando nota de 3.8 a 5.0 directamente en los datos del bloque...")
    bloque1.transacciones[1].nota = 5.0
    print(f"    Nota en memoria ahora:  {bloque1.transacciones[1].nota}  ← ALTERADA")
    esperar(0.3)

    print_step(2, "NIVEL 1 — Detección por el Árbol de Merkle")
    print("    Recalculamos la raíz de Merkle con el dato alterado y la comparamos")
    print("    con la raíz guardada en la cabecera del bloque:\n")
    raiz_guardada = bloque1.merkle_root
    raiz_recalculada = compute_merkle_root(bloque1.transacciones)
    print(f"    Raíz Merkle en cabecera:    {raiz_guardada}")
    print(f"    Raíz Merkle recalculada:    {raiz_recalculada}")
    print(f"    ¿Coinciden?                 {'SÍ' if raiz_guardada == raiz_recalculada else 'NO ← INCONSISTENCIA DETECTADA ✓'}")
    esperar(0.3)

    print_step(3, "NIVEL 2 — Efecto Avalancha y rotura del Proof of Work")
    print("    ¿Qué pasaría si el atacante intenta 'reparar' la cabecera actualizando")
    print("    la raíz de Merkle con el valor recalculado (sin recalcular el nonce)?\n")
    hash_guardado = bloque1.hash
    bloque_temp = Block(
        index=bloque1.index,
        timestamp=bloque1.timestamp,
        transacciones=bloque1.transacciones,
        merkle_root=raiz_recalculada,
        hash_anterior=bloque1.hash_anterior,
        nonce=bloque1.nonce
    )
    hash_con_merkle_nuevo = bloque_temp.calculate_hash()
    print(f"    Hash original (válido, cumple PoW '000'): {hash_guardado}")
    print(f"    Hash recalculado con nueva raíz Merkle:   {hash_con_merkle_nuevo}")
    cumple_pow = hash_con_merkle_nuevo.startswith('000')
    print(f"    ¿El nuevo hash cumple con el PoW ('000')? {'SÍ' if cumple_pow else 'NO ← [¡SISTEMA INVALIDADO!] El Proof of Work se ha ROTO'}")
    print(f"\n    Conclusión: El efecto avalancha del SHA-256 hace que un solo cambio de")
    print(f"    bit en la nota cambie la raíz de Merkle y produzca un hash de bloque completamente diferente.")
    print(f"    Como el nuevo hash no empieza con '000', el bloque se vuelve inválido y la red lo rechaza de inmediato.")
    print(f"    El atacante necesitaría REMINAR este bloque (y todos los posteriores) para que el sistema lo acepte.")
    esperar(0.3)

    print_step(4, "NIVEL 3 — Firma digital ECDSA inválida")
    print("    Aunque el atacante lograse reminar el bloque, la firma ECDSA de la")
    print("    transacción aún apunta al payload original (nota=3.8).\n")
    tx_alterada = bloque1.transacciones[1]
    payload_nuevo = tx_alterada.get_canonical_payload()   # con nota=5.0
    firma_original = tx_alterada.firma
    es_valida_firma = verify_signature(tx_alterada.pk_hex, payload_nuevo, firma_original)
    print(f"    Payload con nota alterada: '{payload_nuevo}'")
    print(f"    Firma almacenada (original): {firma_original[:40]}...")
    print(f"    verify_signature(nueva_nota, firma_original) → {es_valida_firma} {'← FIRMA INVÁLIDA ✓' if not es_valida_firma else ''}")
    esperar(0.3)

    print_step(5, "Validación formal con is_chain_valid()")
    print("    La función recorre todos los bloques ejecutando todas las verificaciones:\n")
    es_valida_ataque = blockchain.is_chain_valid(contract)
    print(f"\n    Resultado: {'CADENA VÁLIDA' if es_valida_ataque else 'CADENA INVÁLIDA — ALTERACIÓN DETECTADA [✓]'}")
    assert es_valida_ataque is False

    print_step(6, "Restaurar el estado original")
    bloque1.transacciones[1].nota = nota_original
    es_restaurada = blockchain.is_chain_valid(contract)
    print(f"    Nota restaurada a {nota_original}. Estado de la cadena: {'VÁLIDA [✓]' if es_restaurada else 'INVÁLIDA [✗]'}")
    assert es_restaurada is True
    print_ok("Escenario 3 completado — el ataque fue detectado en 3 niveles independientes.")
    esperar(0.5)


    # =========================================================================
    # ESCENARIO 4: Intentos de emisión no autorizada
    # =========================================================================
    print_title("ESCENARIO 4 — Intentos de Emisión No Autorizada (Smart Contract)")
    print("""
  El Smart Contract actúa como guardián en origen, antes de que cualquier
  transacción sea admitida al pool de minado. Simularemos 3 ataques:

    Ataque A: Un estudiante intenta auto-registrar una nota usando su ID.
    Ataque B: Un atacante externo suplanta al docente con su propia clave.
    Ataque C: Un atacante usa la clave pública del docente pero firma falsa.
    """)
    esperar(0.3)

    print_step(1, "Generar claves para el Estudiante y el Atacante")
    est_key, est_pub = generate_key_pair()
    atk_key, atk_pub = generate_key_pair()
    print(f"    Estudiante PK (X9.62): {est_pub[:40]}...")
    print(f"    Atacante   PK (X9.62): {atk_pub[:40]}...")
    print(f"\n    NOTA: Ninguno de estos IDs está registrado como profesor en el Smart Contract.")
    esperar(0.3)

    separador(2)
    print_warn("ATAQUE A: Estudiante intenta auto-registrar una nota de 5.0")
    print("""
    El estudiante EST_202601 construye una transacción con su propio ID
    como emisor ('id_profesor = EST_202601') y la firma con su clave privada.
    El Smart Contract verificará si 'EST_202601' está en el registro de profesores.
    """)
    tx_estudiante = Transaction("EST_202601", "EST_202601", "Criptologia", 5.0, est_key, est_pub)
    print(f"    Transacción construida: payload = '{tx_estudiante.get_canonical_payload()}'")
    print(f"    Firma del estudiante:   {tx_estudiante.firma[:40]}...")
    print(f"\n    Enviando al Smart Contract...")
    try:
        blockchain.add_transaction(tx_estudiante, contract)
        print("    [FALLO DE SEGURIDAD] ¡El sistema aceptó la transacción del estudiante!")
    except PermissionError as e:
        print(f"\n    Excepción capturada:\n      {e}")
        print_ok("Ataque A rechazado — el estudiante no tiene rol de profesor registrado.")
    esperar(0.3)

    separador(2)
    print_warn("ATAQUE B: Atacante suplanta al Docente con su propia clave privada/pública")
    print("""
    El atacante usa el ID legítimo del docente ('PROF_ESPEJO') pero adjunta
    su propia clave pública (atk_pub) y firma con su propia clave privada.

    Regla que falla: La PK_hex provista (atk_pub) ≠ PK_hex registrada (prof_pub).
    """)
    tx_suplantador = Transaction("PROF_ESPEJO", "EST_202601", "Criptologia", 5.0, atk_key, atk_pub)
    print(f"    ID del docente usado:   PROF_ESPEJO  (legítimo)")
    print(f"    PK adjunta (atacante):  {atk_pub[:40]}...")
    print(f"    PK registrada (docente):{prof_pub[:40]}...")
    print(f"    ¿Coinciden las PK?      {'SÍ' if atk_pub == prof_pub else 'NO ← diferente ✓'}")
    print(f"\n    Enviando al Smart Contract...")
    try:
        blockchain.add_transaction(tx_suplantador, contract)
        print("    [FALLO DE SEGURIDAD] ¡El sistema aceptó la suplantación!")
    except PermissionError as e:
        print(f"\n    Excepción capturada:\n      {e}")
        print_ok("Ataque B rechazado — la clave pública adjunta no coincide con la registrada.")
    esperar(0.3)

    separador(2)
    print_warn("ATAQUE C: Atacante usa la clave pública del Docente pero firma con su clave privada")
    print("""
    El atacante es más sofisticado: usa el ID del docente Y adjunta la PK
    legítima del docente (prof_pub), pero la transacción fue FIRMADA con
    la clave privada del atacante (atk_key).

    Esto pasa la verificación de identidad (Regla 1) y de clave (Regla 2),
    pero falla en la verificación de la firma ECDSA (Regla 3): la firma
    producida por atk_key no puede verificarse con prof_pub.
    """)
    tx_firma_falsa = Transaction("PROF_ESPEJO", "EST_202601", "Criptologia", 5.0, atk_key, prof_pub)
    payload_falso = tx_firma_falsa.get_canonical_payload()
    firma_falsa = tx_firma_falsa.firma
    verif_con_prof_pub = verify_signature(prof_pub, payload_falso, firma_falsa)
    print(f"    ID usado:               PROF_ESPEJO  (legítimo)")
    print(f"    PK adjunta:             prof_pub (legítima, la del docente)")
    print(f"    Firma hecha con:        atk_key  (clave privada del atacante)")
    print(f"    verify_signature(prof_pub, payload, firma_de_atk_key) → {verif_con_prof_pub} {'← INVÁLIDA ✓' if not verif_con_prof_pub else ''}")
    print(f"\n    Enviando al Smart Contract...")
    try:
        blockchain.add_transaction(tx_firma_falsa, contract)
        print("    [FALLO DE SEGURIDAD] ¡El sistema aceptó la firma falsificada!")
    except PermissionError as e:
        print(f"\n    Excepción capturada:\n      {e}")
        print_ok("Ataque C rechazado — la firma ECDSA no corresponde a la clave privada del docente.")
    esperar(0.3)

    # =========================================================================
    # RESUMEN FINAL
    # =========================================================================
    print_title("RESUMEN FINAL — Resultados de la Demostración EduChain")
    print("""
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Escenario 1 (Bloque Génesis):             COMPLETADO Y VÁLIDO [✓]  │
  │  Escenario 2 (Emisión y PoW):              COMPLETADO Y MINADO  [✓]  │
  │  Escenario 3 (Modificación Histórica):     DETECTADO Y RECHAZADO[✓]  │
  │  Escenario 4A (Fraude: Estudiante):        DETECTADO Y RECHAZADO[✓]  │
  │  Escenario 4B (Fraude: Suplantación PK):   DETECTADO Y RECHAZADO[✓]  │
  │  Escenario 4C (Fraude: Firma Falsa):       DETECTADO Y RECHAZADO[✓]  │
  └─────────────────────────────────────────────────────────────────────┘

  EduChain ha demostrado robustez criptográfica en:

    1. INTEGRIDAD (SHA-256 + Merkle): Cualquier alteración de un bit en una
       nota histórica produce un hash completamente diferente por el efecto
       avalancha, rompiendo la cadena de hashes encadenados.

    2. AUTENTICIDAD Y NO REPUDIO (ECDSA SECP256K1): Solo el poseedor de la
       clave privada del docente puede producir firmas válidas. Ningún
       atacante puede falsificar o suplantar una firma sin la clave privada.

    3. CONSENSO Y RESISTENCIA (Proof of Work): Alterar un bloque histórico
       requeriría reminar ese bloque y todos los posteriores, lo que implica
       un gasto computacional prohibitivo en una red real.

    4. CONTROL DE ACCESO EN ORIGEN (Smart Contract): Las transacciones
       fraudulentas son rechazadas antes de llegar al pool de minado,
       manteniendo la cadena libre de datos maliciosos desde el inicio.
    """)
    separador(1)

if __name__ == '__main__':
    main()
