from graph import graph
import re
alvo          = input("Digite o nome ou cpf do alvo: ")
prompt_usuario = input("Diga o que você deseja buscar: ")

emails_prompt = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', prompt_usuario)
config = {"configurable": {"thread_id": alvo.replace(" ", "_").lower()}}

# Tenta recuperar o checkpoint no banco SQLite via Thread ID.
# Se achar, o LangGraph injeta a memória anterior; se não, inicia do zero.
estado_salvo = graph.get_state(config)

if estado_salvo and estado_salvo.values:
    # já tem execução anterior — não passa estado_inicial
    # o LangGraph carrega do banco automaticamente
    print(f"\n[memória] investigação anterior encontrada para: {alvo}")
    print(f"[memória] resultados anteriores: {len(estado_salvo.values.get('results', []))}")
    print(f"Resultado salvo {estado_salvo.values.get("results", [])}")
    estado_para_invocar = None
else:
    # primeira execução — passa estado_inicial do zero
    print(f"\n[nova investigação] iniciando para: {alvo}")
    estado_para_invocar = {
        "target":         alvo,
        "prompt_usuario": prompt_usuario,
        "messages":       [],
        "argumento":      "",
        "emails": emails_prompt,
        "results":        [],
        "next_action":    "",
        "tentativas":     0,
        "has_cpf":        False,  
        "has_nome":       False   
    }


for evento in graph.stream(estado_para_invocar, config=config):
    nome_do_no = list(evento.keys())[0]
    print(f"\n[nó executado: {nome_do_no}]")