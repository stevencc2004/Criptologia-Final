# ⛓️ Sistema Descentralizado y Seguro de Calificaciones

Este proyecto consiste en el diseño e implementación de un prototipo funcional de **Blockchain local** escrito en Python, orientado específicamente a asegurar, auditar y transparentar la emisión y el registro de calificaciones académicas. 

El sistema demuestra que es matemáticamente imposible alterar una calificación histórica almacenada en la cadena sin que la red detecte de forma inmediata la manipulación física o lógica.

**Asignatura:** Criptología  
**Carrera:** Ingeniería en Telemática  
**Universidad Distrital Francisco José de Caldas**  
**Docente:** Msc. Ing. Óscar Gabriel Espejo Mojica  

---

## 🎯 Objetivo Central del Proyecto

Construir una cadena de bloques local en Python que integre primitivas de **hashing SHA-256**, un **Árbol de Merkle** binario, firmas digitales **ECDSA** (curva SECP256K1) y un algoritmo de consenso **Proof of Work (PoW)**, gobernado por una capa de **Smart Contract** que restrinja la emisión de calificaciones exclusivamente a docentes autorizados mediante firmas criptográficas.

---

## 🛠️ Arquitectura y Componentes Criptográficos

El sistema implementa de manera estricta los siguientes cinco pilares de seguridad:

1. **Hash SHA-256**: Cada bloque posee su identificador criptográfico (`hash`) calculado únicamente sobre la cabecera. Cualquier alteración a nivel de bit en los campos produce un efecto avalancha inmediata que invalida la cadena.
2. **Árbol de Merkle**: Las transacciones de cada bloque (las calificaciones académicas) se resumen de forma binaria hasta obtener un hash único de 256 bits (`merkle_root`) guardado en la cabecera del bloque. Esto permite verificar la integridad de las transacciones históricas sin necesidad de procesar los datos completos del bloque.
3. **ECDSA (Firma Digital)**: Cada transacción contiene la firma digital del docente emisor. La firma se calcula sobre el payload canónico (`ID_Profesor|ID_Estudiante|Asignatura|Nota`) y solo puede producirse utilizando la clave privada ECDSA bajo la curva elíptica **SECP256K1**.
4. **Proof of Work (PoW)**: Consenso descentralizado local donde se busca un valor entero (`nonce`) de modo que el hash resultante de la cabecera inicie exactamente con la dificultad de red requerida (por defecto, dificultad `3`, validando hashes que comiencen con `'000'`).
5. **Smart Contract (Capa de Autorización)**: Verifica en origen que el emisor de la transacción esté formalmente registrado como profesor, que la clave pública provista (`PK_hex`) coincida exactamente con la registrada para ese docente en formato **X9.62 no comprimido** (130 caracteres con prefijo `'04'`), y que la firma digital ECDSA sea válida.

---

## 📂 Estructura de Módulos

El proyecto se encuentra organizado en los siguientes módulos auto-explicativos y documentados con docstrings:

* **`crypto_utils.py`**: Contiene la inicialización de la curva elíptica SECP256K1, la generación del par de claves, el hash SHA-256 y la verificación de firmas digitales.
* **`merkle_tree.py`**: Computa la raíz de Merkle agrupando las transacciones de forma binaria. Incluye manejo para número de transacciones impares y vacías.
* **`smart_contract.py`**: Gestiona el registro asociativo de profesores autorizados y efectúa el control de acceso en origen mediante la verificación criptográfica tripartita (Identidad, Coincidencia de Clave y Firma).
* **`blockchain.py`**: Modela el bloque (`Block`), la cabecera (index, timestamp, merkle_root, hash_anterior, nonce), el pool de transacciones pendientes, el proceso de minado y la validez general de la cadena (`is_chain_valid`).
* **`demo.py`**: Script ejecutable principal que simula en consola e integra los 4 escenarios obligatorios de auditoría.

---

## 🚀 Guía de Uso e Instalación

### Requisitos Previos

El proyecto requiere de **Python 3** y únicamente la biblioteca estándar del sistema junto con la librería de criptografía oficial de Python (`cryptography`):

```bash
pip install cryptography
```

### Ejecutar la Demostración

Una vez instalada la dependencia, puedes iniciar el flujo de verificación y simulación ejecutando el script interactivo desde tu consola:

```bash
python demo.py
```

---

## 🔍 Escenarios de Validación en `demo.py`

Al ejecutar el script de demostración, se verificarán secuencialmente los siguientes escenarios:

### Escenario 1: Creación del Bloque Génesis
* Inicializa la blockchain y el Smart Contract.
* Crea y mina el bloque 0 (Génesis) con un hash inicial que cumple la dificultad `'000'` y con `hash_anterior` e `merkle_root` inicializados en 64 ceros.
* Valida criptográficamente que la cadena vacía sea considerada 100% válida.

### Escenario 2: Emisión Autorizada y Minado de Notas
* Genera llaves ECDSA y registra formalmente a un docente legítimo (`PROF_ESPEJO`).
* El docente emite 3 notas válidas para diferentes estudiantes y las firma digitalmente.
* El Smart Contract valida y acepta las notas en la pool de transacciones pendientes.
* Se mina el **Bloque 1**, calculando su raíz de Merkle y buscando el nonce correcto mediante PoW (mostrando intentos y tiempos transcurridos).

### Escenario 3: Ataque de Modificación Histórica (Tampering)
* Un atacante altera una nota en el bloque minado (cambia una nota histórica de 3.8 a 5.0).
* Se demuestra matemáticamente que la raíz de Merkle recalculada difiere de la almacenada en la cabecera.
* Se demuestra el efecto avalancha: si se modifica la cabecera para actualizar la raíz de Merkle, el hash del bloque cambia por completo y pierde la dificultad de minado PoW.
* La función `is_chain_valid()` detecta de inmediato la manipulación física y rechaza la cadena completa.

### Escenario 4: Intentos de Emisión No Autorizada (Fraudes en Origen)
* Se simulan y rechazan tres tipos de fraudes antes de ingresar al pool de minado:
  1. **Estudiante intenta firmar una nota**: El Smart Contract lo rechaza porque el emisor no está registrado en el directorio de profesores.
  2. **Atacante externo suplanta firma con su clave propia**: El Smart Contract lo rechaza porque la clave pública provista para la firma no coincide con la clave pública previamente registrada para el identificador del docente legítimo.
  3. **Atacante intenta falsificar la firma con la clave pública del profesor**: El Smart Contract lo rechaza debido a un error criptográfico de firma inválida (al no poseer la clave privada del docente).

---

## 🔒 Decisiones Criptográficas y Justificación

* **ECDSA vs RSA**: Se seleccionó **ECDSA SECP256K1** debido a que produce firmas digitales compactas (~70-72 bytes en comparación con los 256 bytes de RSA-2048), reduciendo drásticamente el almacenamiento en disco y la sobrecarga de red en la cadena. Adicionalmente, cuenta con el mismo estándar de seguridad matemática empleado en Bitcoin y Ethereum.
* **Hash de Cabecera Independiente**: En cumplimiento riguroso con el diseño de Satoshi Nakamoto, el hash de bloque opera únicamente sobre los metadatos de cabecera (`index`, `timestamp`, `merkle_root`, `hash_anterior`, `nonce`). La exclusión de los datos crudos de transacciones en el hashing directo de cabecera garantiza que el bloque pueda ser auditado a nivel de integridad a gran velocidad empleando únicamente su estructura Merkle asociada.
