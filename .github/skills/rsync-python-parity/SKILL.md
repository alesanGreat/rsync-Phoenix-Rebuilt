# Skill: rsync-python-parity

## Purpose
Guía al agente para mantener **paridad 1:1** con el código fuente C de rsync (protocolos 20–32) usando este repo como referencia principal.

Esta skill se enfoca en:
- localizar la fuente C relevante en `rsync-original-source-code/`
- escoger la suite correcta para validar el cambio
- evitar regresiones de wire protocol / checksums / matching

## When to Use (Triggers)
Usa esta skill cuando el usuario pida:
- “paridad 1:1”, “igual que rsync C”, “comparar con match.c/checksum.c/token.c/io.c”
- “corrige diferencias contra el original”, “port exacto”, “wire protocol”
- “debug de false alarms”, “hash hits”, “token stream”, “receive_data”

## Key Repo Facts
- Implementación monolítica en `rsync_phoenix_rebuilt.py`.
- Referencia C en `rsync-original-source-code/`.
- La validación de paridad ya existe en tests y herramientas del repo.

## Guardrails
- No reescribir arquitectura: respetar el diseño monolítico.
- Cambios mínimos y justificados; si algo cambia wire-format, actualizar tests/serialización afectada.
- Evitar “aproximaciones”: si el objetivo es 1:1, buscar el comportamiento exacto en C y replicarlo.

## Standard Workflow
### 1) Identificar la pieza C equivalente
Según el área del cambio, empezar aquí:
- Rolling/weak checksum: `rsync-original-source-code/checksum.c`
- Matching/delta: `rsync-original-source-code/match.c`
- Tokens: `rsync-original-source-code/token.c`
- I/O sum headers / wire: `rsync-original-source-code/io.c`
- Negociación/compat: `rsync-original-source-code/compat.c`

### 2) Encontrar el punto Python correspondiente
- Buscar en `rsync_phoenix_rebuilt.py` el símbolo equivalente (misma semántica) y revisar docstrings de referencia.
- Si no hay docstring/trace, añadirlo **solo si es necesario** para evitar futuras divergencias (sin crear docs nuevos fuera del archivo).

### 3) Validar con tests correctos
Siempre correr al menos:
- `python test_protocol_parity.py`

Y según el área:
- checksums: `python test_cross_validation.py`
- matching end-to-end: `python test_end_to_end.py`

### 4) Si hay discrepancia
- Reproducir el caso mínimo.
- Comparar paso a paso contra la fuente C y/o herramienta `compare_with_c.py`.
- Corregir el root-cause (no parche superficial).

## Output Expectations
Al finalizar, reportar:
- qué archivo C fue la referencia
- qué suite(s) se corrieron
- si el cambio afecta wire-format (sí/no)

## Examples
- “Asegura que `send_token/recv_token` es 1:1 con token.c y corre paridad.”
- “Estoy viendo false_alarms altos: guía de diagnóstico y test que lo capture.”
