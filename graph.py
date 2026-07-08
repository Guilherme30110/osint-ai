from langgraph.graph import StateGraph, END
from state import AgentState
from nodes import raciocinar, buscar_dorks, consulta_whois, buscar_processos, buscar_mandados, verificar_leak, gerar_resumo, finalizar
import sqlite3
from langgraph.checkpoint.sqlite import SqliteSaver

def decidir_proximo_passo(state: AgentState) -> str:
    # Trava de segurança: impede que a LLM fique em loop infinito gerando 
    # dorks repetidas. Corta no numero de tentativas e empurra pra esteira de leaks.
    if state["tentativas"] >= 6 or state["next_action"] == "finalizar":
        return "verificar_leak"
    return state["next_action"]

def rotear_pos_leak(state: AgentState) -> str:
    """Roteador 2: Avalia se deve buscar processos baseado na flag da LLM"""
    if state.get("has_cpf", False):
        return "buscar_processos"
    return "avaliar_mandados" 

def rotear_pos_processos(state: AgentState) -> str:
    # Consulta as flags que a própria LLM extraiu no início. 
    # Só aciona o scraper do CNJ (que é pesado) se realmente houver 
    # um nome ou CPF válido.
    if state.get("has_cpf", False) or state.get("has_nome", False):
        return "buscar_mandados"
    return "gerar_resumo"


builder = StateGraph(AgentState)


builder.add_node("raciocinar", raciocinar)
builder.add_node("buscar_dorks", buscar_dorks)
builder.add_node("consulta_whois", consulta_whois)
builder.add_node("verificar_leak", verificar_leak)
builder.add_node("buscar_processos", buscar_processos)
builder.add_node("buscar_mandados", buscar_mandados)
builder.add_node("gerar_resumo", gerar_resumo)
builder.add_node("finalizar", finalizar)


builder.set_entry_point("raciocinar")


builder.add_conditional_edges("raciocinar", decidir_proximo_passo, {
    "buscar_dorks": "buscar_dorks",
    "consulta_whois": "consulta_whois",
    "verificar_leak": "verificar_leak"
})


builder.add_edge("buscar_dorks", "raciocinar")
builder.add_edge("consulta_whois", "raciocinar")

builder.add_conditional_edges("verificar_leak", rotear_pos_leak, {
    "buscar_processos": "buscar_processos",
    "avaliar_mandados": "buscar_mandados" 
})


builder.add_conditional_edges("buscar_processos", rotear_pos_processos, {
    "buscar_mandados": "buscar_mandados",
    "gerar_resumo": "gerar_resumo"
})


builder.add_edge("buscar_mandados", "gerar_resumo")


builder.add_edge("gerar_resumo", "finalizar")
builder.add_edge("finalizar", END)


conn = sqlite3.connect("osint_memory.db", check_same_thread=False)
memory = SqliteSaver(conn)
graph = builder.compile(checkpointer=memory)
print(graph.get_graph().draw_ascii())