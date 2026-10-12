import json
import ollama

def suggest_task_attribute(task_name, task_type="", valid_attributes=None):
    """
    Forces Ollama to select STRICTLY one of the valid dropdown options
    and provide a concise rationale in proper English.
    Determinismo massimo con temperature=0.1.
    """
    if not valid_attributes or len(valid_attributes) == 0:
        valid_attributes = [
            "PEC communication",
            "Mail communication",
            "Post office communication",
            "Online",
            "Offline",
            "Interoperability"
        ]

    name_lower = str(task_name).lower()
    type_lower = str(task_type).lower()

    # Regole contestuali stringenti per i task tipici di processo
    if any(k in name_lower for k in ["rifiuto", "notifica", "ricezione", "richiesta", "esito", "autorizzazione", "istanza"]):
        context_guideline = "Formal administrative communication or official notification requiring non-repudiation and legal validity. MANDATORY: Select 'PEC communication'."
    elif any(k in name_lower for k in ["condition report", "redazione", "perizia", "ispezione", "imballaggio", "trasporto", "consegna"]):
        context_guideline = "Physical inspection, on-site reporting, or material handling activity. MANDATORY: Select 'Offline'."
    elif "send" in type_lower:
        context_guideline = "Outbound dispatch of official notices. Priority: 'PEC communication'."
    elif "receive" in type_lower:
        context_guideline = "Formal request intake. Priority: 'PEC communication'."
    elif "user" in type_lower:
        context_guideline = "User operational activity: select 'Online' if executed on internal portal/system, or 'Offline' if manual/physical."
    else:
        context_guideline = "Select the most coherent execution vector among the available options."

    prompt = f"""
You are a BPMN Security Analyst and Threat Modeling Specialist.
Assign the most secure and appropriate technical execution channel to this task.

Task Details:
- Task Name: "{task_name}"
- Task Type: "{task_type}"
- Guideline: {context_guideline}

ALLOWED OPTIONS:
{json.dumps(valid_attributes, ensure_ascii=False)}

MANDATORY RULES:
1. "selected_attribute" MUST match EXACTLY one string from the ALLOWED OPTIONS list.
2. If the guideline specifies a channel (e.g. 'PEC communication' for official notifications or 'Offline' for physical reports), you MUST select that exact value.
3. "confidence_reason": 1 concise sentence in formal English explaining why this channel ensures security compliance.

Respond STRICTLY with this JSON schema:
{{
    "selected_attribute": "<exact value from allowed options>",
    "confidence_reason": "<concise rationale in English>"
}}
"""

    try:
        response = ollama.chat(
            model='llama3.2',
            messages=[{'role': 'user', 'content': prompt}],
            format='json',
            options={'temperature': 0.1}
        )
        return json.loads(response['message']['content'])
    except Exception as e:
        print(f"Error Ollama Task: {e}")
        return None


def suggest_data_attributes(data_name):
    """
    Evaluates GDPR classification, payload sizing, and load dependency for a Data Object in English.
    Determinismo massimo con temperature=0.1.
    """
    name_clean = str(data_name).lower()

    is_confidential_doc = any(k in name_clean for k in ['contratto', 'polizza', 'fascicolo', 'prestito', 'richiesta', 'documento', 'anagrafica', 'utente', 'cliente', 'contract', 'policy', 'file', 'loan', 'identit'])
    is_technical_log = any(k in name_clean for k in ['condition report', 'report', 'log', 'stato', 'esito', 'ricevuta', 'status', 'receipt', 'immagine', 'acquisita', 'tiff', 'jpg', 'scan'])

    if is_confidential_doc:
        guidelines = """
- This data object represents legal, contractual, administrative, or identity records (e.g. contracts, loan files, insurance policies, identity cards).
- MANDATORY: It contains Personally Identifiable Information (PII/GDPR). Set "personal": "1".
- MANDATORY: Document records are not negligible in size. Set "order_of_size": "kilobyte" (or "megabyte") and "size": 50.
- Set "load_dependence": between 1 and 3.
"""
    elif is_technical_log:
        guidelines = """
- This data object is an operational status report, high-resolution diagnostic image, or technical log (e.g. Condition Report, master TIFF).
- MANDATORY: Set "personal": "0" (it contains cultural artifact diagnostics, not human personal data).
- For diagnostic master images (TIFF) set "order_of_size": "megabyte" or "gigabyte" with size around 50 to 500.
- Set "load_dependence": 1.
"""
    else:
        guidelines = """
- Determine whether personal data is involved (personal='1') or strictly system metadata (personal='0').
- Standard digital artifacts range around "kilobyte" scale.
"""

    prompt = f"""
You are a Senior GDPR Compliance and Data Architecture Specialist for Cybersecurity Threat Modeling.
Analyze the following Data Object: "{data_name}"

GUIDELINES:
{guidelines}

RESPONSE REQUIREMENTS:
1. "personal": "1" if it contains personal / GDPR / identifiable data, "0" otherwise.
2. "order_of_size": choose STRICTLY from ["byte", "kilobyte", "megabyte", "gigabyte"].
3. "size": realistic integer estimate (e.g. 50).
4. "load_dependence": integer from 1 to 5.
5. "reason": concise, professional rationale in English (strictly 1 sentence).

Respond STRICTLY in valid JSON format:
{{
    "personal": "1",
    "order_of_size": "kilobyte",
    "size": 50,
    "load_dependence": 1,
    "reason": "<rationale in formal English>"
}}
"""

    try:
        response = ollama.chat(
            model='llama3.2',
            messages=[{'role': 'user', 'content': prompt}],
            format='json',
            options={'temperature': 0.1}
        )
        return json.loads(response['message']['content'])
    except Exception as e:
        print(f"Error LLM DataObject: {e}")
        return None

# Alias per compatibilità con importazioni singolare/plurale
suggest_data_attribute = suggest_data_attributes


def generate_risk_executive_summary(process_name, threats, controls):
    """
    Generates a professional English Executive Summary on the process risk profile
    and the mitigation coverage provided by the identified CIS controls.
    """
    prompt = f"""
You are a Chief Information Security Officer (CISO) and expert in STRIDE Threat Modeling and the CIS Controls Framework.
Analyze the following security posture for the workflow: "{process_name}"

IDENTIFIED THREAT VECTORS (STRIDE):
{json.dumps(threats, ensure_ascii=False)}

RECOMMENDED DEFENSIVE SAFEGUARDS (CIS CONTROLS):
{json.dumps(controls, ensure_ascii=False)}

TASK:
Write a concise, high-level Executive Summary (strictly 3 to 4 sentences) in formal, technical English.
Highlight the primary integrity/confidentiality risk exposures discovered across the process boundaries and explain how the aligned CIS controls systematically mitigate operational vulnerabilities.

Respond STRICTLY and EXCLUSIVELY in valid JSON format:
{{
    "summary": "<concise professional summary in English>"
}}
"""
    try:
        response = ollama.chat(
            model='llama3.2',
            messages=[{'role': 'user', 'content': prompt}],
            format='json',
            options={'temperature': 0.2}
        )
        data = json.loads(response['message']['content'])
        return data.get('summary', '')
    except Exception as e:
        print(f"Error LLM Executive Summary: {e}")
        return None

def suggest_threat_agent_profile(system_name="Art Loan System"):
    """
    Deduce il profilo dei Threat Agent, motivazioni e bersagli sensibili
    perfettamente allineato ai valori dei checkbox del Threat Agent Wizard.
    """
    prompt = f"""
You are a Senior Cyber Threat Intelligence Specialist in the Cultural Heritage sector.
Analyze the threat landscape and adversary profile for the following system/organization: "{system_name}"

TASK:
You must select the most appropriate options for the Threat Agent questionnaire.

ALLOWED VALUES FOR EACH QUESTION:
- "q1": MUST be strictly "Yes" or "No".
- "q2": MUST be strictly one of:
    ["Consider as 'trusted' the employees", "Consider all threat agents"]
- "q3": MUST be a JSON array containing one or more of strictly:
    ["Copy", "Deny", "Destroy", "Damage", "Take", "All"]
- "q4": MUST be a JSON array containing one or more of strictly:
    ["Theft", "Cause harm", "Embarassment", "Tech Advantage", "Business Advantage"]
- "reason": Exactly 1 concise sentence in formal English summarizing the operational threat environment.

Respond STRICTLY with this JSON schema:
{{
    "q1": "Yes",
    "q2": "Consider all threat agents",
    "q3": ["Take", "Copy", "Damage"],
    "q4": ["Theft", "Cause harm", "Business Advantage"],
    "reason": "Cultural heritage loan processes exhibit elevated risks of targeted physical theft, unauthorized disclosure, and operational disruption."
}}
"""
    try:
        response = ollama.chat(
            model='llama3.2',
            messages=[{'role': 'user', 'content': prompt}],
            format='json',
            options={'temperature': 0.1}
        )
        return json.loads(response['message']['content'])
    except Exception as e:
        print(f"Error Threat Agent LLM: {e}")
        # Fallback deterministico conforme ai checkbox HTML reali
        return {
            "q1": "Yes",
            "q2": "Consider all threat agents",
            "q3": ["Take", "Copy", "Damage"],
            "q4": ["Theft", "Cause harm", "Business Advantage"],
            "reason": "The system processes high-value cultural artifacts and confidential transit logistics, presenting critical exposures to insider and external actors."
        }


# ==============================================================================
# ORGANIZATIONAL CONTEXT & RISK APPETITE POLICY (D.Lgs. 42/2004 & D.M. 29/01/2008)
# Dati trattati esclusivamente in locale (on-premise via Ollama) a tutela della riservatezza
# ==============================================================================
DEFAULT_POLICY_CONTEXT = """
La procedura per il prestito in Italia (D.Lgs. 42/2004, art. 48; D.M. 29 gennaio 2008; D.P.C.M. 271/2010):
- Richiesta di autorizzazione da trasmettere a mezzo PEC con anticipo di almeno 4 mesi. Termine procedimentale: 90 giorni.
- Documenti obbligatori: Elenco beni con stima valore assicurativo e custode, Progetto scientifico, Facility Report, Polizza assicurativa da chiodo a chiodo (nail-to-nail all-risks inclusiva di furto con destrezza).
- Condizioni di sicurezza e conservazione: riproduzione fotografica/scansione preventiva obbligatoria, vigilanza permanente, microclima controllato (16-20°C, 50-60% UR, max 50 lux), teche antisfondamento.
"""

def evaluate_stride_risk_appetite(element_name="Case Study Workflow", element_type="Asset", policy_document_text=None, temperature=0.6):
    """
    Evaluates OWASP impact factors (scale 1 to 9) and STRIDE severity levels (Low, Medium, High, Critical)
    for an element based strictly on the uploaded policy document text using local Llama 3.2.
    Temperatura impostata di default a 0.6 (deduttiva) e parametrizzabile per lo script test_runs_stability.py.
    """
    context_to_use = policy_document_text.strip() if policy_document_text and policy_document_text.strip() else DEFAULT_POLICY_CONTEXT

    prompt = f"""
You are a Cybersecurity Expert and Risk Analyst in the Cultural Heritage domain following the official OWASP Risk Rating Methodology.

TARGET TO EVALUATE:
Name: "{element_name}"
Type: "{element_type}"

INSTITUTIONAL POLICY & CONTEXT DOCUMENT PROVIDED BY USER:
\"\"\"
{context_to_use}
\"\"\"

TASK:
Based strictly on the institutional policy document above, evaluate the OWASP IMPACT factors (scale 1 to 9, where 1-3 is Low, 4-6 is Medium, 7-9 is High/Critical) for this target in relation to the STRIDE threat categories.

Evaluate both:
1. TECHNICAL IMPACT FACTORS (Scale 1-9):
   - Loss of Confidentiality (e.g. disclosure of transport routes, insurance values)
   - Loss of Integrity (e.g. alteration of Condition Report, damage to the artwork)
   - Loss of Availability (e.g. interruption of statutory 90-day window, system outage)
   - Loss of Accountability / Traceability (e.g. lack of certified PEC, missing signatures)

2. BUSINESS IMPACT FACTORS (Scale 1-9):
   - Financial Damage (e.g. loss of insurance coverage, costs of irreversible damage)
   - Reputation Damage (e.g. public scandal, loss of international museum trust)
   - Non-compliance (e.g. violation of D.Lgs. 42/2004 or ministerial decrees)
   - Privacy Violation (e.g. exposure of collector names, guards or curators PII)

Then map the resulting severity (LOW, MEDIUM, HIGH, CRITICAL) for each applicable STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) providing the specific textual quote or evidence from the document.

CRITICAL: Return ONLY a valid JSON object matching this exact schema:
{{
  "owasp_impact_factors": {{
    "loss_of_confidentiality": 7,
    "loss_of_integrity": 9,
    "loss_of_availability": 8,
    "loss_of_accountability": 8,
    "financial_damage": 8,
    "reputation_damage": 8,
    "non_compliance": 8,
    "privacy_violation": 6
  }},
  "evaluations": [
    {{
      "category": "Tampering",
      "severity": "CRITICAL",
      "rationale": "Alteration of Condition Report or climate parameters violates D.M. 29/01/2008 and compromises nail-to-nail insurance coverage.",
      "evidence_quote": "garantire le seguenti condizioni di conservazione e sicurezza: riproduzione di tutti i documenti... Polizza assicurativa da chiodo a chiodo"
    }},
    {{
      "category": "Information Disclosure",
      "severity": "HIGH",
      "rationale": "Exposing declared insured values or transport logistics increases theft risks during transit.",
      "evidence_quote": "descrivere ciascuna delle opere... ed il valore per cui sarà assicurata"
    }},
    {{
      "category": "Denial of Service",
      "severity": "HIGH",
      "rationale": "System or workflow delays risk exceeding the statutory 90-day window required by D.P.C.M. 271/2010.",
      "evidence_quote": "Il procedimento di autorizzazione al prestito... si conclude entro 90 giorni dall'istanza"
    }},
    {{
      "category": "Repudiation",
      "severity": "HIGH",
      "rationale": "Failure to use PEC for formal communications undermines non-repudiation and ministerial legal validity.",
      "evidence_quote": "Alla richiesta di autorizzazione al prestito, da trasmettere a mezzo PEC"
    }},
    {{
      "category": "Spoofing",
      "severity": "MEDIUM",
      "rationale": "Identity spoofing of delegates or curators could lead to unauthorized release of the asset.",
      "evidence_quote": "indicando il responsabile della sua custodia"
    }},
    {{
      "category": "Elevation of Privilege",
      "severity": "HIGH",
      "rationale": "Unauthorized permission escalation over catalog databases or vaults exposes priceless heritage to unauthorized access.",
      "evidence_quote": "vigilanza permanente nella sede di esposizione"
    }}
  ]
}}
"""

    try:
        response = ollama.chat(
            model='llama3.2',
            messages=[{'role': 'user', 'content': prompt}],
            format='json',
            options={'temperature': float(temperature)}
        )
        return json.loads(response['message']['content'])
    except Exception as e:
        print(f"Error LLM Risk Appetite: {e}")
        # Fallback deterministico conforme a OWASP e alla normativa
        return {
            "owasp_impact_factors": {
                "loss_of_confidentiality": 7,
                "loss_of_integrity": 9,
                "loss_of_availability": 8,
                "loss_of_accountability": 8,
                "financial_damage": 8,
                "reputation_damage": 8,
                "non_compliance": 8,
                "privacy_violation": 6
            },
            "evaluations": [
                {
                    "category": "Tampering",
                    "severity": "CRITICAL",
                    "rationale": "Compromissione del Condition Report o dei parametri ambientali (D.M. 29/01/2008), con invalidazione della polizza nail-to-nail.",
                    "evidence_quote": "Polizza assicurativa da chiodo a chiodo, con formula all risks included"
                },
                {
                    "category": "Information Disclosure",
                    "severity": "HIGH",
                    "rationale": "Diffusione non autorizzata dei valori di polizza o dettagli logistici (D.Lgs. 42/2004).",
                    "evidence_quote": "descrivere ciascuna delle opere... ed il valore per cui sarà assicurata"
                },
                {
                    "category": "Denial of Service",
                    "severity": "HIGH",
                    "rationale": "Superamento della finestra perentoria di 90 giorni ex D.P.C.M. 271/2010.",
                    "evidence_quote": "Il procedimento... si conclude entro 90 giorni dall'istanza"
                },
                {
                    "category": "Repudiation",
                    "severity": "HIGH",
                    "rationale": "Mancato ricorso alla PEC per la notifica formale dell'istanza.",
                    "evidence_quote": "da trasmettere a mezzo PEC"
                },
                {
                    "category": "Spoofing",
                    "severity": "MEDIUM",
                    "rationale": "Impersonificazione del responsabile della custodia indicato nell'istanza.",
                    "evidence_quote": "indicando il responsabile della sua custodia"
                },
                {
                    "category": "Elevation of Privilege",
                    "severity": "HIGH",
                    "rationale": "Accesso non autorizzato ai sistemi di catalogazione o vigilanza perimetrale.",
                    "evidence_quote": "vigilanza permanente nella sede di esposizione"
                }
            ]
        }

# Alias per piena compatibilità con i controller di Django
evaluate_risk_appetite_with_llm = evaluate_stride_risk_appetite