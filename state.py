from typing import TypedDict, Annotated
from operator import add

class AgentState(TypedDict):
    target:      str                    # quem estamos investigando
    prompt_usuario:     str
    messages:    Annotated[list, add]   # histórico de mensagens
    results:     Annotated[list, add]   # resultados coletados
    next_action: str                    # próxima ação decidida pela LLM
    tentativas: int                     # de vezes que o nó de raciocínio foi executado
    argumento: str                      # o que estamos pesquisando
    emails: Annotated[list, add]
    busca_privada_feita: bool
    resumo_final: str
    has_cpf: bool
    has_nome: bool