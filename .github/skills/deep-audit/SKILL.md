# Skill: Auditoría Profunda del Workspace (rsync-python)

Este skill define cómo realizar auditorías exhaustivas y meticulosas del proyecto **rsync-python** (implementación Python 1:1 del protocolo rsync).

## Cuándo usar este skill
- El usuario menciona "auditar", "revisar", "buscar", "encontrar", "corregir" en el contexto del proyecto
- Pide verificar algo en "todo el proyecto", "todos los archivos"
- Quiere asegurarse de que algo se cumple en todo el codebase
- Menciona "análisis", "scan", "inspección", "validar", "verificar"
- Pide revisar "paridad", "protocolo", "checksums", "matching", "wire protocol"

## ⚠️ REGLA FUNDAMENTAL

**NO tomar atajos. NO limitarse a "algunos archivos". NO conformarse con tests.**

Cuando el usuario pide una auditoría o revisión, espera que sea:
- **Exhaustiva**: TODOS los archivos relevantes, sin excepciones
- **Meticulosa**: Cada archivo debe ser inspeccionado apropiadamente
- **Documentada**: Reportar qué se revisó y qué se encontró

## Metodología de Auditoría Profunda

### Paso 1: Descubrir el Alcance Completo

Antes de revisar nada, determinar CUÁNTOS archivos hay:

```bash
# Contar archivos Python principales
find . -name "*.py" -type f | grep -v "__pycache__" | grep -v "rsync-original-source-code" | wc -l

# Listar TODOS los archivos Python principales
find . -name "*.py" -type f | grep -v "__pycache__" | grep -v "rsync-original-source-code"

# Contar archivos de test
find . -name "test_*.py" -type f | wc -l
```

**OBLIGATORIO**: Informar al usuario cuántos archivos se van a revisar ANTES de empezar.

### Paso 2: Usar Herramientas de Búsqueda Masiva

#### Para patrones de texto (search_files)
```python
# Buscar patrón en TODO el proyecto
search_files con regex="patrón" y file_pattern="**/*.py"

# Buscar en tipos específicos de archivo
search_files con file_pattern="**/rsync_phoenix_rebuilt.py"
search_files con file_pattern="**/test_*.py"
```

#### Para nombres de archivo (list_files)
```bash
# Buscar archivos por patrón
list_files con query="**/*checksum*.py"
list_files con query="**/*protocol*.py"
list_files con query="**/*test*.py"
```

### Paso 3: Procesar Resultados Sistemáticamente

**NO parar en los primeros resultados.** Si hay 50 coincidencias, revisar las 50.

Para cada hallazgo:
1. Leer el contexto completo del archivo
2. Determinar si es un problema real o falso positivo
3. Documentar la ubicación exacta (archivo + línea)
4. Clasificar por severidad si aplica

### Paso 4: Crear Script de Auditoría (cuando aplique)

Para auditorías complejas, crear un script que automatice la revisión:

```python
#!/usr/bin/env python3
"""
Auditoría: Buscar usos de función deprecated o patrón problemático.
"""
import os
import re
import sys

def find_patterns(root_dir, pattern, exclude_dirs=("__pycache__", "rsync-original-source-code")):
    """Busca patrón en todos los archivos Python."""
    issues = []
    regex = re.compile(pattern)
    
    for root, dirs, files in os.walk(root_dir):
        # Excluir directorios
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        for i, line in enumerate(lines, 1):
                            if regex.search(line):
                                issues.append(f"{filepath}:{i}: {line.strip()}")
                except Exception as e:
                    print(f"Error leyendo {filepath}: {e}")
    
    return issues

# Ejemplo de uso
if __name__ == "__main__":
    pattern = r"funcion_deprecated\s*\("
    issues = find_patterns(".", pattern)
    
    print(f"Encontrados {len(issues)} usos:\n")
    for issue in issues:
        print(f"  - {issue}")
```

### Paso 5: Reportar Resultados Completos

El reporte DEBE incluir:

1. **Alcance**: "Revisé X archivos de tipo Y"
2. **Metodología**: "Usé search_files para buscar Z"
3. **Hallazgos**: Lista completa, no resumen
4. **Estadísticas**: "Encontré N problemas en M archivos"
5. **Próximos pasos**: Qué hacer con los hallazgos

## Estrategias por Tipo de Auditoría

### Auditoría de Paridad con C (rsync-python)
```bash
# Buscar TODO el código que difiere del C original
# Enfocarse en: checksum.c, match.c, token.c, io.c, compat.c

# Revisar documentación de paridad en AGENTS.md
# Comparar con código fuente en rsync-original-source-code/

# Suite de validación obligatoria
python test_protocol_parity.py
python test_cross_validation.py
```

### Auditoría de Checksums
```bash
# Buscar implementaciones de checksums
search_files: query="class.*Checksum" isRegexp=true file_pattern="**/*.py"

# Validar contra vectores de prueba conocidos
python test_cross_validation.py -v

# Verificar protocolos soportados
search_files: query="protocol.*20|protocol.*21|protocol.*32" isRegexp=true
```

### Auditoría de Protocolo (wire format)
```bash
# Verificar serialize/deserialize de tokens
search_files: query="send_token|recv_token|write_sum_head|read_sum_head" isRegexp=true

# Validar compatibilidad de protocolo
python test_multi_protocol.py
```

### Auditoría de Consistencia de API
```bash
# Encontrar todos los usos de generate_sums/generate_signature
search_files: query="generate_sums|generate_signature|generate_delta" isRegexp=true

# Verificar que todos los dataclasses tengan serialización
search_files: query="to_dict|from_dict" isRegexp=true
```

### Auditoría de Tests
```bash
# Listar todos los archivos de test
find . -name "test_*.py" -type f

# Contar tests por archivo
python -m unittest discover -v 2>&1 | grep "test_" | wc -l
```

### Auditoría de TODO/FIXME/HACK
```bash
search_files: query="TODO|FIXME|HACK|XXX|BUG" isRegexp=true file_pattern="**/*.py"
# Listar TODOS, no resumir
```

### Auditoría de Imports/Dependencies
```bash
# Python
search_files: query="^import|^from" isRegexp=true file_pattern="**/rsync_phoenix_rebuilt.py"

# Verificar dependencias externas
cat requirements.txt 2>/dev/null || pip list | grep -E "xxhash|lz4|zstandard"
```

## ⛔ Lo que NUNCA hacer

1. **NO decir "revisé algunos archivos"** - Especificar cuántos exactamente
2. **NO parar en los primeros 5-10 resultados** - Procesar TODOS
3. **NO asumir que "no hay más"** - Verificar con conteos
4. **NO limitarse a ejecutar tests** - Los tests no cubren todo
5. **NO dar resúmenes vagos** - Dar números y ubicaciones concretas
6. **NO ignorar archivos de test** - Los tests son parte del proyecto
7. **NO comparar con rsync externo** - Usar solo `rsync-original-source-code/` como referencia

## Ejemplo de Auditoría Correcta

❌ **MAL**:
> "Revisé el código y encontré algunos usos de la función deprecated. 
> Los tests pasan, así que debería estar bien."

✅ **BIEN**:
> "Auditoría de `funcionDeprecated()` en rsync-python:
> 
> **Alcance**: 15 archivos Python (excluyendo rsync-original-source-code/ y __pycache__)
> 
> **Metodología**: search_files con regex `funcionDeprecated\s*\(` en **/*.py
> 
> **Hallazgos** (3 usos en 2 archivos):
> 1. `rsync_phoenix_rebuilt.py:<línea>` - Usado en ChecksumEngine.generate_sums()
> 2. `rsync_phoenix_rebuilt.py:<línea>` - Usado en ChecksumEngine.match_sums()
> 3. `test_cross_validation.py:89` - Uso en test existente
> 
> **Recomendación**: Verificar contra código C en checksum.c:100-150 antes de cambiar.
> Suite a ejecutar: `python test_cross_validation.py`"

## Herramientas Disponibles

| Herramienta | Uso | Cuándo usar |
|-------------|-----|-------------|
| `search_files` | Buscar texto/regex | Patrones conocidos en archivos Python |
| `list_files` | Buscar archivos | Por nombre/extensión |
| `read_file` | Leer contenido | Inspección detallada |
| `list_files` | Listar carpetas | Entender estructura |
| `execute_command` | Scripts custom | Auditorías complejas |
| `focus_chain` | Delegar subtareas | Dividir trabajo grande |

## Para Auditorías Muy Grandes (1000+ archivos Python)

1. **Dividir por carpetas**: Auditar `rsync_phoenix_rebuilt.py` (~9200+ líneas) primero
2. **Usar focus_chain**: Delegar partes específicas de la auditoría
3. **Crear scripts**: Automatizar la detección
4. **Reportar progreso**: "Completado: checksums (2 archivos). Siguiente: matching"

## Contexto Específico de rsync-python

### Archivos Clave del Proyecto

| Archivo | Propósito | Líneas (~) |
|---------|-----------|------------|
| `rsync_phoenix_rebuilt.py` | Implementación monolítica | 9200+ |
| `test_cross_validation.py` | Validación de checksums | - |
| `test_protocol_parity.py` | Tests de paridad C | - |
| `test_multi_protocol.py` | Tests multi-protocolo | - |
| `compare_with_c.py` | Herramienta de comparación C | - |

### Áreas de Auditoría Prioritarias

1. **Rolling checksum**: `checksum.c:100-250` (C) → `rsync_phoenix_rebuilt.py` (Python)
2. **Matching algorithm**: `match.c:100-500` (C) → `rsync_phoenix_rebuilt.py` (Python)
3. **Token protocol**: `token.c:300-400` (C) → `rsync_phoenix_rebuilt.py` (Python)
4. **I/O wire format**: `io.c:1900-2100` (C) → `rsync_phoenix_rebuilt.py` (Python)

### Constantes de Protocolo (referencia)

```python
# De lib/md-defines.h (C)
CSUM_LE = 2      # Little-endian checksum
CSUM_BE = 3      # Big-endian checksum

# De rsync.h (C)
CPRES_PER_BLOCK = 1      # Por bloque
CPRES_NEVER = 0xFFFFFFFF # Nunca comprimir
```

## Validación Final

Antes de reportar "auditoría completa", verificar:

- [ ] ¿Conté cuántos archivos había del tipo relevante?
- [ ] ¿Revisé/busqué en TODOS ellos?
- [ ] ¿Documenté CADA hallazgo con ubicación exacta?
- [ ] ¿El usuario puede verificar mis resultados?
- [ ] ¿Propuse acciones concretas para los hallazgos?
- [ ] ¿Incluí referencia al código C fuente (`rsync-original-source-code/`)?
