
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from state import AgentState
from ddgs import DDGS
from bs4 import BeautifulSoup
import json 
import time
import re
import whois
from langdetect import detect
import requests
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
import os
import speech_recognition as sr
from pydub import AudioSegment
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import static_ffmpeg

static_ffmpeg.add_paths()

cookies = []

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Configura o Jinja2 para procurar NESTE diretório (não em uma subpasta)
env = Environment(loader=FileSystemLoader(BASE_DIR))


template = env.get_template('relatorio.html')

# temperature=0 é lei aqui para manter o agente previsível e garantir
# que ele siga a estrutura do JSON sem alucinar nas decisões.
llm = ChatOllama(model="qwen3:14b-q4_K_M", temperature=0, think=False)

def raciocinar(state: AgentState) -> dict:
    system_prompt = """Você é um analista de OSINT experiente e metódico.
Seu objetivo é investigar o alvo usando as ferramentas disponíveis de forma inteligente, sem repetir comandos.

FERRAMENTAS E SEUS ARGUMENTOS OBRIGATÓRIOS (Escolha apenas UMA ação por vez):

1. acao: "buscar_dorks"
   - O que faz: Pesquisa no Google usando operadores avançados de OSINT.
   - argumento: A string exata da dork.
   - REGRA DE ASPAS: identificadores exatos (CPF, CNPJ, telefone, e-mail, nome completo) SEMPRE entre aspas. Operadores (site:, filetype:, inurl:, OR, -site:) ficam FORA das aspas.
   - REGRA DE VARIAÇÕES (importante): quando existir mais de uma variação do MESMO dado, combine todas em UMA ÚNICA dork usando OR, ao invés de criar dorks separadas para cada variação. Isso vale para:
     - CPF/CNPJ com e sem pontuação: "097.774.788-36" OR "09777478836"
     - Telefone com e sem formatação: "(11) 91234-5678" OR "11912345678"
     - Mais de um e-mail fornecido: "email1@dominio.com" OR "email2@dominio.com"
     Nunca gere uma dork só com a versão pontuada e depois, em outra chamada, a versão sem pontuação — isso deve ser uma única dork desde o início.
   - REGRA DE ESPECIFICIDADE: priorize identificadores únicos (CPF, CNPJ, telefone, e-mail) antes de nome próprio — nome é o termo mais ambíguo e gera mais ruído. Teste cada identificador (já combinando suas variações via OR, conforme regra acima) antes de avançar para o nome isolado.
   - REGRA DE COMBINAÇÃO COM OPERADOR: só combine uma entidade com site:/filetype:/inurl: depois que a busca dessa entidade (já com suas variações via OR) tiver retornado ao menos um resultado com conteúdo real (title ou url preenchidos). Nunca combine mais de 2 entidades fortes na mesma dork.
   - REGRA PARA EMAIL: e-mails combinados via OR (regra acima) NUNCA devem ser combinados com site:, filetype: ou inurl: na mesma dork.
   - Se uma dork não retornar resultados, NÃO tente variações dela com os mesmos termos base — mude completamente a abordagem (próxima entidade ou próximo tipo de combinação).
   - Não repita dorks já executadas (verifique o histórico antes de responder).

2. acao: "consulta_whois"
   - O que faz: Traz dados de registro de um domínio.
   - argumento: o domínio raiz extraído da URL (ex: de "https://www.exemplo.com.br/pagina" use "exemplo.com.br").
   - REGRA DE USO: execute sempre que existir um domínio ainda não consultado — seja porque o usuário mencionou uma URL/domínio no prompt, seja porque uma dork já retornou uma URL com conteúdo — mesmo que o usuário não peça "whois" explicitamente. Priorize essa ação assim que um domínio novo aparecer, antes de gerar mais dorks.
   - Nunca repita whois para um domínio já consultado.

3. acao: "finalizar"
   - O que faz: Encerra sua participação na investigação.
   - argumento: "" (vazio).
   - Use quando: (a) os identificadores (com variações já combinadas) e o nome do alvo já foram testados e combinados conforme as regras acima, (b) todo domínio identificado (no prompt ou nos resultados) já foi consultado via whois, e (c) não há dork ou domínio novo plausível a tentar. Resultado vazio de uma entidade NÃO significa investigação concluída — significa apenas abandonar aquela entidade e seguir para a próxima.

REGRAS DE SAÍDA:
- Responda EXCLUSIVAMENTE com um JSON válido.
- NÃO adicione textos explicativos, marcações markdown ou comentários fora ou dentro do JSON.
- O campo "motivo" deve ser breve e explicar o porquê desta ferramenta ter sido escolhida agora.

ANÁLISE DE ENTIDADES (Obrigatório preencher em toda resposta):
- "has_cpf": Defina como true se houver um CPF no prompt do usuário (com ou sem pontuação).
- "has_nome": Defina como true se houver um Nome próprio ou Razão Social no prompt.

EXEMPLO DE RESPOSTA VALIDA 1:
{
  "acao": "buscar_dorks",
  "argumento": "\"000.000.000-00\" OR \"00000000000\"",
  "motivo": "Testando CPF isolado, já combinando as variações com e sem pontuação em uma única dork."
  "has_cpf": true,
  "has_nome": true"
}

EXEMPLO DE RESPOSTA VALIDA 2:
{
  "acao": "buscar_dorks",
  "argumento": "\"exemplo1@dominio.com\" OR \"exemplo2@dominio.com\"",
  "motivo": "Buscando exposições dos e-mails fornecidos pelo usuário, combinados entre si via OR."
  "has_cpf": true,
  "has_nome": true"
}

EXEMPLO DE RESPOSTA VALIDA 3:
{
  "acao": "consulta_whois",
  "argumento": "exemplo.com.br",
  "motivo": "Domínio encontrado em resultado de dork e ainda não consultado; priorizando whois antes de novas buscas."
  "has_cpf": true,
  "has_nome": true"
}

EXEMPLO DE RESPOSTA VALIDA 4:
{
  "acao": "buscar_dorks",
  "argumento": "\"Nome Completo Alvo\" site:linkedin.com",
  "motivo": "Nome isolado já retornou resultado com conteúdo; combinando com site:linkedin.com para restringir a fonte mais provável."
  "has_cpf": true,
  "has_nome": true"
}

EXEMPLO DE RESPOSTA VALIDA 5:
{
  "acao": "finalizar",
  "argumento": "",
  "motivo": "Identificadores (com variações) e nome já testados e combinados; domínios encontrados já consultados via whois; nenhuma dork nova plausível resta."
  "has_cpf": true,
  "has_nome": true"
}
"""

    context = (f"Prompt do usuario: {state['prompt_usuario']}\n"
               f"Alvo: {state['target']}\n"
               f"Tentativas feitas: {state['tentativas']}\n"
               f"Resultados coletados: {state['results']}\n"
               f"Faça busca por dorks até ser suficiente, sem repetir dorks"
               f"Resultados vazios ou sem conteúdo não necessariamente contam como investigação concluída.\n"
               f"Decida a próxima ação a tomar."
               f"Se o pedido já foi atendido com os resultados coletados, use finalizar."
               )
    
    resposta = llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content=context)])
    
    try:
        texto = resposta.content
        # Força bruta para isolar o JSON: ignora qualquer texto extra 
        # (tipo "Aqui está o resultado:") que a LLM possa cuspir em volta.
        inicio = texto.find("{")
        fim = texto.rfind("}") + 1
        json_str = texto[inicio:fim]
        try:
         decisao = json.loads(json_str)
        except json.JSONDecodeError:
         json_str = re.sub(r':\s*"(.*?)"(?=\s*[,}])', lambda m: ': "' + re.sub(r'(?<!\\)"', r'\"', m.group(1)) + '"', json_str, flags=re.DOTALL)
         decisao = json.loads(json_str)

        # .get com valor padrão — se a chave não existir no JSON
        # usa o valor padrão em vez de lançar KeyError
        proxima_acao = decisao.get("acao", "finalizar")
        argumento    = decisao.get("argumento", state["target"])
        has_cpf      = decisao.get("has_cpf", False)
        has_nome     = decisao.get("has_nome", False)
        # proteção contra valor inválido no campo "acao"
        # se a LLM inventar um nome que não existe no mapa
        # do add_conditional_edges, o grafo quebraria com KeyError
        acoes_validas = ["buscar_dorks", "consulta_whois", "finalizar"]
        if proxima_acao not in acoes_validas:
            proxima_acao = "finalizar"

    except Exception as e:
        proxima_acao = "finalizar"
        print(f"  [ERRO]: {e}")
        print(f"  [texto recebido]: {texto}")
        argumento    = state["target"]

    return {
        "messages":    [resposta],
        "next_action": proxima_acao,
        "argumento":   argumento,
        "tentativas":  state["tentativas"] + 1,
        "has_cpf":     has_cpf,
        "has_nome":    has_nome
    }


def buscar_dorks(state: AgentState) -> dict:
    query = state["argumento"]
    dorks_encontradas = []
    try:
        results = DDGS().text(query, region="br-pt", backend="google", max_results=20)
        for result in results:
            title = result['title']
            url = result['href']
            body = result['body']
            if(detect(body) == 'pt'):
             if not any(url in dork_encontrada for dork_encontrada in dorks_encontradas):
                dorks_encontradas.append({
                 "query": query, 
                 "title": title,
                 "url": url
                })
        if not dorks_encontradas:
            print("Nada encontrado para essa dork.")
            dorks_encontradas.append({
                "query": query,
                "title": "",
                "url": ""
            })
        return {"results": dorks_encontradas}
    except Exception as e:
        print(f"Ocorreu um erro na busca: {e}")
        return {"results": [{
            "query": query,
            "title": "",
            "url": ""
        }]}

def consulta_whois(state: AgentState) -> dict:
    try:
        nome_dominio = state["argumento"]
        print(nome_dominio)
        dominio = whois.whois(nome_dominio)
        email        = ", ".join(dominio['email'])        if isinstance(dominio['email'], list)        else dominio['email']
        person       = ", ".join(dominio['person'])       if isinstance(dominio['person'], list)       else dominio['person']
        name         = ", ".join(dominio['registrant_name']) if isinstance(dominio['registrant_name'], list) else dominio['registrant_name']
        cpf          = dominio['registrant_id']
        name_servers = ", ".join(dominio['name_servers']) if isinstance(dominio['name_servers'], list) else dominio['name_servers']
        return {
         "results": [{
          "fonte": "whois",
          "dominio": nome_dominio,
          "email": email,
          "person": person,
          "name": name,
          "cpf": cpf,
          "name_servers": name_servers
         }]
        }
    except Exception as e:
        print(f"Erro durante a função de whois: {e}")
        return {"results": []}

def verificar_leak(state: AgentState) -> dict:
 emails = state.get("emails", [])
 emails_unicos = list(set(emails))
 if not emails_unicos:
  return {"results": [{"fonte": "leak", "email": "", "breaches": 0, "services": []}]}   
 resultados_vazamento = []
 for email in emails_unicos:
  req = requests.get(f"https://hackmyip.com/api/breach?email={email}").json()
  breaches = req['data']['breaches']
  services = req['data']['services']
  services_str = ", ".join(services) if services else "Nenhum serviço listado"
  resultados_vazamento.append({
    "fonte": "leak",
    "email": email,
    "breaches": breaches,
    "services": services if services else []
  })
 return {"results": resultados_vazamento}

def gerar_resumo(state: AgentState) -> dict:   
 dados_consolidados = {
  "termo_pesquisado_inicial": state["target"],
  "resultados": [r for r in state["results"] if isinstance(r, dict)] # Contém title, link/href e body
 }    
 system_prompt = """Você é um analista de inteligência cibernética sênior em OSINT.
Sua tarefa é analisar os dados recebidos no JSON e gerar um resumo analítico estritamente técnico e factual.

Você recebeu 'resultados' que contêm os campos: title, href/link, resultado de consulta de processos e mandados de prisão).

DIRETRIZES OBRIGATÓRIAS DE FORMATAÇÃO:
1. TEXTO PURO EM PARÁGRAFOS: Escreva a resposta exclusivamente em formato de texto corrido, estruturado apenas por parágrafos normais.
2. PROIBIDO MARKDOWN: Não use nenhum asterisco (como **texto** ou *texto*) em nenhuma parte do texto.
3. PROIBIDO LISTAS E MARCADORES: É terminantemente proibido usar travessões ou hifens (-), pontos de listagem (•) ou números (como 1., 2., 1), a), b)) para enumerar itens ou criar tópicos.
4. TRANSIÇÃO NATURAL: Para separar os assuntos, use conectivos e transições textuais normais no início dos parágrafos, como por exemplo: "Em relação ao perfil cadastral do alvo...", "No que diz respeito às buscas estruturadas por dorks...", "A respeito da análise dos vazamentos e brechas de segurança...", "Concluindo a verificação técnica...".

DIRETRIZES OBRIGATÓRIAS DE ANÁLISE:
1. TRATAMENTO DE PERFIL AUSENTE: Se 'perfil_confirmado_do_alvo' for nulo, significa que a investigação não obteve ou não focou em dados cadastrais (CPF, mãe, endereço). Baseie o seu resumo EXCLUSIVAMENTE na análise dos artefatos (e-mails, domínios, sites) presentes em 'resultados_das_dorks'. Não tente inventar ou supor dados civis para o alvo principal.
2. ANÁLISE BASEADA EM LINKS E TITLES: Avalie detalhadamente os campos 'title', 'href' e o conteúdo do 'body' de cada dork. Aponte no seu resumo quais sites/fontes retornaram dados relevantes sobre os artefatos pesquisados.
3. ISOLAMENTO COMPLETO (ANTI-VÍNCULO FALSO): Se o usuário pesquisou múltiplos elementos (ex: um nome, dois e-mails e um site), trate cada um de forma independente. PROIBIDO declarar ou sugerir que um e-mail ou site pertence ao termo pesquisado inicial A MENOS que o conteúdo ('body') ou o 'title' de algum resultado prove essa relação de forma explícita e irrefutável.
4. SE DEU MISS, APENAS COMENTE: Se as dorks de um e-mail vierem sem conteúdo relevante (vazias ou falsos positivos), descreva apenas: "Artefato [X] verificado em fontes abertas, sem ocorrências ativas identificadas".
5. Não use dados externos ou suposições que não estejam estritamente documentadas dentro do JSON fornecido.
6. Verificar leak só verifica vazamento de email caso houver e se o email for informado do usuario"""

 resposta = llm.invoke([
  SystemMessage(content=system_prompt),
  HumanMessage(content=json.dumps(dados_consolidados, ensure_ascii=False, indent=2))
 ])  
 return { "resumo_final": resposta.content, "messages": [resposta] }



def solver_captcha():
 # Bypass automatizado do reCAPTCHA v2.
 # Abandona o desafio de imagens e resolve o de áudio convertendo 
 # para wav e usando o SpeechRecognition local para matar o desafio.
 global cookies
 driver = webdriver.Chrome()
 URL_BNMP = "https://portalbnmp.cnj.jus.br/#/login"
 driver.get(URL_BNMP)
 try:
  wait = WebDriverWait(driver, 20)
  print("[CAPTCHA] Aguardando o iframe do reCAPTCHA carregar...")
  wait.until(EC.frame_to_be_available_and_switch_to_it((By.CSS_SELECTOR, "iframe[title='reCAPTCHA']")))
  print("[CAPTCHA] Clicando no checkbox...")
  wait.until(EC.element_to_be_clickable((By.ID, "recaptcha-anchor"))).click()
  driver.switch_to.default_content()
  time.sleep(2)
  print("[CAPTCHA] Entrando no iframe do desafio...")
  wait.until(EC.frame_to_be_available_and_switch_to_it((By.CSS_SELECTOR, "iframe[title*='desafio']")))
  print("[CAPTCHA] Alternando para o desafio de áudio...")
  wait.until(EC.element_to_be_clickable((By.ID, "recaptcha-audio-button"))).click()
  time.sleep(2)
  audio_source = wait.until(EC.presence_of_element_located((By.ID, "audio-source"))).get_attribute("src")
  resposta_audio = requests.get(audio_source, stream=True)
  with open("audio.mp3", "wb") as f:
   for chunk in resposta_audio.iter_content(chunk_size=1024):
    if chunk:
     f.write(chunk)
  sound = AudioSegment.from_mp3("audio.mp3")
  sound.export("audio.wav", format="wav")
  print("[CAPTCHA] Traduzindo o áudio em texto...")
  reconhecedor = sr.Recognizer()
  with sr.AudioFile("audio.wav") as fonte:
   dados_audio = reconhecedor.record(fonte)
   texto_resolvido = reconhecedor.recognize_google(dados_audio, language="en-US")
  print(f"[CAPTCHA] Texto encontrado: {texto_resolvido}")
  campo_resposta = wait.until(EC.presence_of_element_located((By.ID, "audio-response")))
  campo_resposta.send_keys(texto_resolvido)
  time.sleep(1)
  wait.until(EC.element_to_be_clickable((By.ID, "recaptcha-verify-button"))).click()
  print("[CAPTCHA] Resolvido!")
  driver.switch_to.default_content()
  time.sleep(2)
  cookies_selenium = driver.get_cookies()
  if cookies_selenium:
   cookies.append(cookies_selenium[0]["value"])
   print("[CAPTCHA] Cookie capturado com sucesso.")
  time.sleep(2)
 except Exception as e:
  print(f"[CAPTCHA] Erro no processo de bypass: {e}")
 finally:
  for arquivo in ["audio.mp3", "audio.wav"]:
   if os.path.exists(arquivo):
    os.remove(arquivo)
  driver.quit()


def buscar_processos(state: AgentState) -> dict:
    argumento_ia = str(state.get("target", "")) 
    # Pega o cpf no state target e limpa qualquer pontuação. 
    # O Escavador precisa da string numérica pura para a query.
    cpf_limpo = "".join(re.findall(r'\d', argumento_ia))
    print(f"[Processos] Iniciando busca para o CPF: {cpf_limpo}")
    url_busca = "https://www.escavador.com/busca"
    params = {'q': cpf_limpo, 'qo': 't'}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'pt-BR,pt;q=0.9',
        'Referer': 'https://www.escavador.com/',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
       }

    dados_filtrados = {
        "fonte": "processos",
        "perfil_nome": "",
        "perfil_descricao": "",
        "resumo_pessoa": "",
        "detalhes_processos": [],
        "detalhes_processos_parsed": []
    }

    session = requests.Session()
    response = session.get(url_busca, params=params, headers=headers, allow_redirects=True)

    print(f"[Processos] Status: {response.status_code} | CPF: {cpf_limpo}")
    
    if response.status_code != 200:
        return dados_filtrados

    soup = BeautifulSoup(response.text, 'html.parser')
    script_tag = soup.find('script', attrs={'type': 'application/ld+json'})

    if not script_tag:
        print("[Processos] JSON-LD não encontrado. Cookie pode ter expirado.")
        return dados_filtrados

    json_data = json.loads(script_tag.string)
    graph = json_data.get('@graph', [])

    for entidade in graph:
        tipo = entidade.get('@type')
        if tipo == 'ProfilePage':
            dados_filtrados["perfil_nome"] = re.sub(r'CPF\s*[\*\dX\.\-]+', f"CPF {cpf_limpo}", entidade.get('name', '')) 
            dados_filtrados["perfil_descricao"] = entidade.get('description', '')
        elif tipo == 'Person':
            dados_filtrados["resumo_pessoa"] = entidade.get('description', '')
        elif tipo == 'ItemList':
            for item_bloco in entidade.get('itemListElement', []):
                item_interno = item_bloco.get('item', {})
                desc = item_interno.get('description', '')
                if desc:
                    dados_filtrados["detalhes_processos"].append(desc)

    for texto in dados_filtrados["detalhes_processos"]:
        assunto  = re.search(r'Assunto:\s*([^.]+)', texto)
        tribunal = re.search(r'Tribunal\s+(\w+)', texto)
        grau     = re.search(r'(Primeiro Grau|Segundo Grau|Superior)', texto)
        data     = re.search(r'Iniciado em\s+([\d/]+)', texto)
        dados_filtrados["detalhes_processos_parsed"].append({
            "ativo":    "ativo" in texto.lower(),
            "assunto":  assunto.group(1).strip()  if assunto  else "Não identificado",
            "tribunal": tribunal.group(1).strip() if tribunal else "",
            "grau":     grau.group(1).strip()     if grau     else "",
            "data":     data.group(1).strip()     if data     else "",
        })
    print(dados_filtrados)
    print(f"[Processos] {len(dados_filtrados['detalhes_processos'])} processos encontrados.")
    return {"results": [dados_filtrados]}


def buscar_mandados(state: AgentState) -> dict:
 global cookies
 # Delegando a formatação do payload para a IA. É mais seguro ela avaliar 
 # o contexto para definir se a chave vai ser 'numeroCpf' ou 'nomePessoa' do que tentar adivinhar via regex no input livre do usuário.
 system_prompt = """
 Você é um extrator de dados estruturados focado em OSINT.
 Analise o 'Alvo' e o 'Prompt' do usuário e determine a melhor forma de consultar mandados de prisão.
 Priorize o CPF se houver um válido. Caso contrário, use o Nome.
 Responda EXCLUSIVAMENTE em JSON com a seguinte estrutura:
 {
  "tipo": "CPF" ou "NOME",
  "valor": "apenas os numeros do cpf ou o nome completo"
 }
 """
 conteudo_ia = f"Alvo: {state.get('target', '')}\nPrompt: {state.get('prompt_usuario', '')}"
 
 resposta_ia = llm.invoke([
  SystemMessage(content=system_prompt),
  HumanMessage(content=conteudo_ia)
 ])


 try:
  texto = resposta_ia.content
  inicio = texto.find("{")
  fim = texto.rfind("}") + 1
  decisao = json.loads(texto[inicio:fim])
  tipo_consulta = decisao.get("tipo", "NOME").upper()
  valor_consulta = decisao.get("valor", state.get("target", ""))
 except Exception as e:
  print(f"[BNMP] Erro de parsing da IA: {e}. Usando fallback.")
  tipo_consulta = "NOME"
  valor_consulta = state.get("target", "")

 print(f"[BNMP] IA definiu query -> Tipo: {tipo_consulta} | Valor: {valor_consulta}")
 solver_captcha()  # Executa o bypass do reCAPTCHA e captura o cookie
 # 3. Setup da Requisição BNMP
 session = requests.Session()
 url = "https://portalbnmp.cnj.jus.br/bnmpportal/api/pesquisa-pecas/filter"
 params = {
  "page": "0",
  "size": "10",
  "sort": ""
 }
 session.headers.update({
  "Host": "portalbnmp.cnj.jus.br",
  "Sec-Ch-Ua-Platform": '"Windows"',
  "Accept-Language": "pt-BR,pt;q=0.9",
  "Fingerprint": "b2a352b7091851fda50f2a00162c1bb9",
  "Sec-Ch-Ua": '"Not-A.Brand";v="24", "Chromium";v="146"',
  "Sec-Ch-Ua-Mobile": "?0",
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
  "Accept": "application/json",
  "Content-Type": "application/json;charset=UTF-8",
  "Origin": "https://portalbnmp.cnj.jus.br",
  "Sec-Fetch-Site": "same-origin",
  "Sec-Fetch-Mode": "cors",
  "Sec-Fetch-Dest": "empty",
  "Referer": "https://portalbnmp.cnj.jus.br/",
  "Accept-Encoding": "gzip, deflate, br",
  "Priority": "u=1, i"
 })
 
 if cookies:
  token_cookie = cookies[0]
  session.cookies.set(
   name="portalbnmp",
   value=token_cookie,
   domain="portalbnmp.cnj.jus.br"
  )

 # 4. Configuração dos Payloads baseados na decisão da IA
 if tipo_consulta == "CPF":
  valor_limpo = "".join(re.findall(r'\d', str(valor_consulta)))
  payload = {"buscaOrgaoRecursivo": False, "orgaoExpeditor": {}, "numeroCpf": valor_limpo}
 else:
  payload = {"buscaOrgaoRecursivo": False, "orgaoExpeditor": {}, "nomePessoa": str(valor_consulta)}

 response = session.post(url, params=params, json=payload)
 print(f"[BNMP] Status da requisição: {response.status_code}")

 # 5. Tratamento da Resposta
 try:
  resultado = response.json()
  resultado["query_bnmp"] = f"[{tipo_consulta}] {valor_consulta}"
  resultado["fonte"] = "bnmp"
  
  qtd_encontrada = len(resultado.get("content", []))
  print(f"[BNMP] Peças encontradas: {qtd_encontrada}")
  
  if qtd_encontrada > 0:
   baixar_mandados(resultado) 
  
  # Retorna empacotado na estrutura de 'results' do AgentState
  return {"results": [resultado]} 
 except ValueError:
  print(f"[BNMP] Erro ao converter resposta BNMP em JSON: {response.text}")
  return {"results": []}


def baixar_mandados(resultado: dict):
 global cookies
 print("[BNMP] Fazendo download dos mandados de prisão...")
 cookies_dict = {"portalbnmp": cookies[0]}
 for item in resultado.get("content", []):
  id_mandado = item["id"]
  tipo_mandado = item["idTipoPeca"]
  url = f"https://portalbnmp.cnj.jus.br/bnmpportal/api/certidaos/relatorio/{id_mandado}/{tipo_mandado}"
  headers = {
   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
   "Accept": "application/json, text/plain, */*",
   "Accept-Language": "pt-BR,pt;q=0.9",
   "Origin": "https://portalbnmp.cnj.jus.br",
   "Referer": "https://portalbnmp.cnj.jus.br/",
   "Content-Type": "application/json;charset=UTF-8",
   "Priority": "u=1, i"
  }
  response = requests.post(url, headers=headers, cookies=cookies_dict, json={})
  if response.status_code == 200:
   nome_ficheiro = f"PecaResumo-{id_mandado}.pdf"
   with open(nome_ficheiro, "wb") as f:
    f.write(response.content)
   print(f"[BNMP] Mandado salvo: {nome_ficheiro}")
  else:
   print(f"[BNMP] Erro ao baixar mandado {id_mandado}: {response.status_code}")
   print(f"[BNMP] Resposta: {response.text}")


def finalizar(state: AgentState) -> dict:
    target = state["target"]
    dorks = [r for r in state["results"] if isinstance(r, dict) and "query" in r]
    dorks_testadas = len(set(r["query"] for r in dorks))
    dorks_com_resultados = len(set(r["query"] for r in dorks if r.get("url")))
    leaks = [r for r in state["results"] if isinstance(r, dict) and r.get("fonte") == "leak"]
    whois_data = next((r for r in state["results"] if isinstance(r, dict) and r.get("fonte") == "whois"), None)
    processos = next((r for r in state["results"] if isinstance(r, dict) and r.get("fonte") == "processos"), None)
    bnmp = next((r for r in state["results"] if isinstance(r, dict) and r.get("fonte") == "bnmp"), None)
    resumo_ia = state.get("resumo_final", "Nenhum resumo gerado.")
    html_string = template.render(target=target, dorks=dorks,dorks_testadas=dorks_testadas,dorks_com_resultados=dorks_com_resultados,leaks=leaks,whois_data=whois_data,processos=processos,bnmp=bnmp,resumo_ia=resumo_ia)
    html_bytes = html_string.encode('utf-8')
    HTML(string=html_bytes).write_pdf('saida.pdf')