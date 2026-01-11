# Skill: rsync-python-testing

## Purpose
Estandariza cómo ejecutar y diagnosticar rápidamente el estado del proyecto **rsync-python** (tests, reportes y señales de regresión) sin improvisar.

Esta skill **no reemplaza** la documentación del proyecto: usa [AGENTS.md](../../../AGENTS.md) como fuente canónica de detalle y mantiene el repo consistente.

## When to Use (Triggers)
Usa esta skill cuando el usuario pida:
- “corre tests”, “valida que todo pasa”, “reproduce el fallo”, “qué tests ejecutar”
- “verifica paridad”, “confirma que no rompimos nada”, “haz sanity check”
- “genera reporte de tests” o “resumen de resultados”

## Guardrails
- No agregar nuevos documentos de proyecto (la referencia canónica es [AGENTS.md](../../../AGENTS.md)).
- Cambios mínimos: si un test falla, arreglar **solo** lo relacionado con el cambio solicitado.
- Preferir comandos existentes del repo (unittest y scripts ya presentes).

## Standard Workflow
### 1) Quick suite (fast feedback)
Ejecuta discovery de unittest:
- `python -m unittest -q`

### 2) Suites explícitas (cuando se necesita granularidad)
Ejecuta en este orden (de más específico a más amplio):
- `python test_cross_validation.py`
- `python test_protocol_parity.py`
- `python test_multi_protocol.py`
- `python test_comprehensive.py`
- `python test_end_to_end.py`

### 3) Si falla algo
- Captura: nombre de test, traceback, y cuál suite lo disparó.
- Reduce a un caso mínimo (si es posible) sin crear nuevos docs.
- Si el fallo toca paridad/protocolo, deriva a la skill `rsync-python-parity`.

## Output Expectations
Cuando reportes al usuario:
- Qué comando(s) corriste
- Qué falló/pasó (conteo o “ALL PASS”)
- 1–2 hipótesis técnicas si falló, con siguiente acción

## Resources
- Script opcional de conveniencia: `run_tests.sh` (en esta misma carpeta)
- Canon: [AGENTS.md](../../../AGENTS.md)

## Examples
- “Corre la suite rápida y dime si está verde.”
- “Después de cambiar el rolling checksum, corre paridad y cross-validation.”
