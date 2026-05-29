"""
Módulo: smart_contract.py
Asignatura: Criptología - Proyecto Final 
Universidad Distrital Francisco José de Caldas

Este módulo actúa como el Smart Contract del sistema, definiendo la lógica
de negocio académica y aplicando restricciones criptográficas sobre quién
tiene autorización para registrar calificaciones en la blockchain.
"""

from crypto_utils import verify_signature

class SmartContract:
    def __init__(self):
        """
        Inicializa el Smart Contract de calificaciones con un registro de profesores
        vacío. El registro asocia identificadores de profesor con sus claves públicas X9.62.
        """
        # Estructura: { "ID_Profesor": "PK_hex" }
        self.professor_registry = {}

    def register_professor(self, id_profesor: str, pk_hex: str):
        """
        Registra o actualiza la clave pública autorizada para un docente en el sistema.
        Solo los profesores en este registro pueden emitir transacciones válidas.
        
        Args:
            id_profesor (str): Identificador único del profesor (ej. 'PROF_01').
            pk_hex (str): Clave pública ECDSA (130 caracteres, prefijo '04').
        """
        if not pk_hex.startswith("04") or len(pk_hex) != 130:
            raise ValueError("Error de formato: La clave publica debe estar en formato X9.62 de 130 caracteres.")
        self.professor_registry[id_profesor] = pk_hex
        print(f"[Smart Contract] Profesor '{id_profesor}' registrado con exito.")

    def validate_transaction(self, tx) -> bool:
        """
        Aplica las reglas del Smart Contract sobre una transacción de calificación:
        1. Valida que el ID_Profesor emisor esté en el registro de autorizados.
        2. Valida que la clave pública provista en la transacción coincida exactamente con la registrada.
        3. Valida la firma digital ECDSA del emisor sobre el payload canónico.
        
        Args:
            tx: Objeto de transacción (debe proveer id_profesor, pk_hex, firma y método get_canonical_payload()).
            
        Returns:
            bool: True si la transacción cumple todas las reglas de validación criptográficas.
            
        Raises:
            PermissionError: Si falla cualquiera de las reglas de autorización y autenticidad.
        """
        id_profesor = getattr(tx, 'id_profesor', None)
        pk_hex = getattr(tx, 'pk_hex', None)
        firma = getattr(tx, 'firma', None)
        
        # 1. Verificar si el profesor emisor está registrado
        if id_profesor not in self.professor_registry:
            raise PermissionError(
                f"[Fallo Smart Contract] Acceso Denegado: El identificador '{id_profesor}' "
                "no esta registrado en el sistema como Profesor autorizado."
            )

        # 2. Verificar que la clave pública dada coincida con la registrada del profesor
        registered_pk = self.professor_registry[id_profesor]
        if pk_hex != registered_pk:
            raise PermissionError(
                f"[Fallo Smart Contract] Acceso Denegado: La clave publica provista para '{id_profesor}' "
                "no coincide con la clave registrada y autorizada en el Smart Contract."
            )

        # 3. Extraer el payload canónico y verificar la firma digital ECDSA
        if not hasattr(tx, 'get_canonical_payload'):
            raise AttributeError("Error de Estructura: La transaccion no implementa 'get_canonical_payload()'")
            
        payload = tx.get_canonical_payload()
        
        # Verificar la firma
        if not verify_signature(pk_hex, payload, firma):
            raise PermissionError(
                "[Fallo Smart Contract] Acceso Denegado: La firma digital ECDSA es invalida. "
                "Los datos de la nota han sido manipulados o no corresponden a la clave privada del docente."
            )

        return True

# Bloque de prueba de funcionamiento autónomo
if __name__ == '__main__':
    try:
        print("==================================================")
        print("PRUEBA UNITARIA: smart_contract.py")
        print("==================================================")

        # Importamos herramientas para la demo local
        from crypto_utils import generate_key_pair, sign_data

        # 1. Creamos un mock de la clase Transacción para probar
        class MockTransaction:
            def __init__(self, id_profesor, id_estudiante, asignatura, nota, private_key, pk_hex):
                self.id_profesor = id_profesor
                self.id_estudiante = id_estudiante
                self.asignatura = asignatura
                self.nota = nota
                self.pk_hex = pk_hex
                # Firmar
                payload = self.get_canonical_payload()
                self.firma = sign_data(private_key, payload)

            def get_canonical_payload(self) -> str:
                return f"{self.id_profesor}|{self.id_estudiante}|{self.asignatura}|{self.nota}"

        # Instanciar el Smart Contract
        contract = SmartContract()

        # Generamos pares de claves para Profesor, Estudiante y Atacante
        prof_key, prof_pub = generate_key_pair()
        est_key, est_pub = generate_key_pair()
        atk_key, atk_pub = generate_key_pair()

        # Registrar el profesor legítimo en el Smart Contract
        contract.register_professor("PROF_ESPEJO", prof_pub)

        # Caso A: Transacción válida de Profesor
        print("\n--- CASO A: Transaccion legitima de Docente registrado ---")
        tx_valida = MockTransaction("PROF_ESPEJO", "EST_202610", "Criptologia", 4.5, prof_key, prof_pub)
        resultado = contract.validate_transaction(tx_valida)
        print(f"-> Resultado de validacion: {resultado}")
        if resultado is not True:
            raise AssertionError("La transacción del profesor autorizado debería ser válida")
        print("[OK] Transaccion legitima aceptada con exito.")

        # Caso B: Estudiante intenta registrar una nota usando su propio ID
        print("\n--- CASO B: Estudiante intenta emitir nota usando su ID ---")
        tx_estudiante = MockTransaction("EST_202610", "EST_202611", "Criptologia", 5.0, est_key, est_pub)
        try:
            contract.validate_transaction(tx_estudiante)
            raise AssertionError("El Smart Contract no rechazó al estudiante")
        except PermissionError as e:
            print(f"Rechazado correctamente:\n   -> {e}")
            print("[OK] Estudiante sin rol de profesor rechazado exitosamente.")

        # Caso C: Atacante intenta suplantar al profesor usando el ID del profesor pero su propia clave pública y privada
        print("\n--- CASO C: Atacante intenta suplantar al Profesor con clave propia ---")
        tx_suplantacion = MockTransaction("PROF_ESPEJO", "EST_202610", "Criptologia", 5.0, atk_key, atk_pub)
        try:
            contract.validate_transaction(tx_suplantacion)
            raise AssertionError("El Smart Contract no rechazó la suplantación por clave pública")
        except PermissionError as e:
            print(f"Rechazado correctamente:\n   -> {e}")
            print("[OK] Intento de suplantacion de identidad de profesor detectado y rechazado.")

        # Caso D: Atacante intenta suplantar usando la clave pública del profesor pero firmando con su propia clave privada
        print("\n--- CASO D: Atacante intenta suplantar usando PK del Profesor pero firma invalida ---")
        tx_firma_falsa = MockTransaction("PROF_ESPEJO", "EST_202610", "Criptologia", 5.0, atk_key, prof_pub)
        try:
            contract.validate_transaction(tx_firma_falsa)
            raise AssertionError("El Smart Contract no rechazó la firma falsa")
        except PermissionError as e:
            print(f"Rechazado correctamente:\n   -> {e}")
            print("[OK] Intento de falsificacion de firma digital detectado y rechazado.")

        print("\n[OK] ¡Todas las verificaciones del Smart Contract superadas con exito!")
        print("==================================================")
    except AssertionError as ae:
        print(f"[FALLO EN PRUEBAS] {ae}")
        raise
    except Exception as e:
        print(f"[ERROR] Ejecución de pruebas fallida: {e}")
        raise
