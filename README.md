# 🕵️ Agente de OSINT com LangGraph
 
Agente de investigação automatizada em fontes abertas (OSINT), construído como uma máquina de estados com [LangGraph](https://github.com/langchain-ai/langgraph). Um LLM decide dinamicamente qual ferramenta usar a cada passo — dorks, WHOIS, verificação de vazamentos, processos judiciais — com base nos resultados que já foram coletados, em vez de seguir um pipeline fixo.
 
📖 **Explicação completa da arquitetura e das decisões de design:** [link do post no blog]
 
## O que faz
 
- Gera e refina Google Dorks de forma iterativa (entidades isoladas antes de combinadas)
- Consulta WHOIS de domínios encontrados
- Verifica vazamentos de e-mail via API do HackMyIP
- Consulta processos judiciais e mandados em fontes públicas/oficiais (condicionado à presença de CPF/nome)
- Compila os achados e gera um relatório final em PDF via LLM + Jinja2 + WeasyPrint
- Mantém memória entre execuções (checkpoint em SQLite), permitindo retomar uma investigação já iniciada
## Stack
 
`Python` · `LangGraph` · `Ollama` (LLM local) · `SQLite` (checkpointer) · `Jinja2` + `WeasyPrint` (relatório PDF)
 
## Como rodar
 
```bash
git clone https://github.com/Guilherme30110/osint-ai
cd seu-repositorio
pip install -r requirements.txt
python main.py
```
 
Você será solicitado a informar o alvo (nome ou CPF) e o que deseja investigar.
 
## Estrutura
 
```
├── main.py       # ponto de entrada, gerencia a sessão/thread
├── graph.py       # definição do grafo de estados e roteamento
├── nodes.py       # implementação de cada ferramenta/nó
├── state.py       # schema do estado do agente
