import os
import re
import math
import datetime

KNOWLEDGE_DIR = "data/knowledge"


def _ensure_dir():
    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)


def extraer_texto_pdf(archivo_pdf) -> str:
    try:
        import PyPDF2
        lector = PyPDF2.PdfReader(archivo_pdf)
        paginas = []
        for i, pagina in enumerate(lector.pages):
            texto = pagina.extract_text() or ""
            if texto.strip():
                paginas.append(f"[Página {i+1}]\n{texto}")
        return "\n\n".join(paginas)
    except Exception as e:
        return f"Error al leer PDF: {e}"


def guardar_en_base_conocimiento(nombre: str, contenido: str) -> str:
    _ensure_dir()
    nombre_limpio = re.sub(r'[^\w\-.]', '_', nombre)
    ruta = os.path.join(KNOWLEDGE_DIR, f"{nombre_limpio}.txt")
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(contenido)
    return ruta


def listar_documentos(filtro: str = "") -> list:
    """Return list of dicts with real metadata for each indexed document."""
    _ensure_dir()
    docs = []
    for fname in sorted(os.listdir(KNOWLEDGE_DIR)):
        if not fname.endswith(".txt"):
            continue
        ruta = os.path.join(KNOWLEDGE_DIR, fname)
        try:
            stat = os.stat(ruta)
            with open(ruta, encoding="utf-8", errors="ignore") as f:
                contenido = f.read()
            palabras = len(contenido.split())
            fragmentos = max(1, palabras // 100)
            fecha = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d")
            nombre_display = fname.replace(".txt", "").replace("_", " ")
            tamano_kb = round(stat.st_size / 1024, 1)

            if filtro and filtro.lower() not in nombre_display.lower():
                continue

            docs.append({
                "archivo":   fname,
                "nombre":    nombre_display,
                "palabras":  palabras,
                "fragmentos": fragmentos,
                "fecha":     fecha,
                "tamano_kb": tamano_kb,
            })
        except Exception:
            continue
    return docs


def eliminar_documento(nombre_archivo: str) -> bool:
    """Delete a document from the knowledge base."""
    ruta = os.path.join(KNOWLEDGE_DIR, nombre_archivo)
    try:
        os.remove(ruta)
        return True
    except Exception:
        return False


def cargar_contexto_completo() -> str:
    """Load all documents from disk and return concatenated text."""
    _ensure_dir()
    partes = []
    for fname in sorted(os.listdir(KNOWLEDGE_DIR)):
        if not fname.endswith(".txt"):
            continue
        ruta = os.path.join(KNOWLEDGE_DIR, fname)
        try:
            with open(ruta, encoding="utf-8", errors="ignore") as f:
                texto = f.read()
            nombre = fname.replace(".txt", "").replace("_", " ")
            partes.append(f"=== DOCUMENTO: {nombre} ===\n{texto}")
        except Exception:
            continue
    return "\n\n".join(partes)


def _tokenizar(texto: str) -> list:
    return re.findall(r'\b[a-záéíóúüñA-ZÁÉÍÓÚÜÑ]{3,}\b', texto.lower())


def _score_chunk(chunk_tokens: list, query_tokens: set) -> float:
    """TF-IDF-like relevance score between a chunk and the query."""
    if not chunk_tokens:
        return 0.0
    hits = sum(1 for t in chunk_tokens if t in query_tokens)
    return hits / math.log1p(len(chunk_tokens))


def buscar_fragmentos_relevantes(query: str, max_fragmentos: int = 6, chunk_palabras: int = 120) -> list:
    """
    Naive keyword RAG: split documents into chunks, score by query term overlap,
    return the top N most relevant chunks with their source name.
    """
    query_tokens = set(_tokenizar(query))
    if not query_tokens:
        return []

    _ensure_dir()
    candidatos = []

    for fname in os.listdir(KNOWLEDGE_DIR):
        if not fname.endswith(".txt"):
            continue
        ruta = os.path.join(KNOWLEDGE_DIR, fname)
        nombre = fname.replace(".txt", "").replace("_", " ")
        try:
            with open(ruta, encoding="utf-8", errors="ignore") as f:
                texto = f.read()
        except Exception:
            continue

        palabras = texto.split()
        for i in range(0, len(palabras), chunk_palabras):
            chunk = " ".join(palabras[i: i + chunk_palabras])
            tokens = _tokenizar(chunk)
            score = _score_chunk(tokens, query_tokens)
            if score > 0:
                candidatos.append({
                    "fuente":    nombre,
                    "chunk":     chunk,
                    "score":     round(score, 3),
                    "relevancia": 0,
                })

    candidatos.sort(key=lambda x: x["score"], reverse=True)
    top = candidatos[:max_fragmentos]

    if top:
        max_score = top[0]["score"]
        for c in top:
            c["relevancia"] = round((c["score"] / max_score) * 100) if max_score > 0 else 0

    return top


def contar_total_fragmentos() -> int:
    docs = listar_documentos()
    return sum(d["fragmentos"] for d in docs)
