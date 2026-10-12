import math
import json
import ollama

# Testo normativo di riferimento (D.Lgs. 42/2004, D.M. 29/01/2008, D.P.C.M. 271/2010)
POLICY_TEXT = """
La procedura per il prestito in Italia (D.Lgs. 42/2004, art. 48; D.M. 29 gennaio 2008; D.P.C.M. 271/2010):
- Richiesta di autorizzazione da trasmettere a mezzo PEC con anticipo di almeno 4 mesi. Termine procedimentale: 90 giorni.
- Documenti obbligatori: Elenco beni con stima valore assicurativo e custode, Progetto scientifico, Facility Report, Polizza assicurativa da chiodo a chiodo (nail-to-nail all-risks inclusiva di furto con destrezza).
- Condizioni di sicurezza e conservazione: riproduzione fotografica/scansione preventiva obbligatoria, vigilanza permanente, microclima controllato (16-20°C, 50-60% UR, max 50 lux), teche antisfondamento.
"""

PROMPT = f"""You are a Cybersecurity Expert and Risk Analyst in the Cultural Heritage domain following the official OWASP Risk Rating Methodology.

TARGET TO EVALUATE:
Name: "Fascicolo di prestito"
Type: "Asset"

INSTITUTIONAL POLICY & CONTEXT DOCUMENT PROVIDED BY USER:
\"\"\"
{POLICY_TEXT}
\"\"\"

TASK:
Based strictly on the institutional policy document above, evaluate the OWASP IMPACT factors (scale 1 to 9, where 1-3 is Low, 4-6 is Medium, 7-9 is High/Critical) for this target in relation to the STRIDE threat categories.

Evaluate both:
1. TECHNICAL IMPACT FACTORS (Scale 1-9):
   - Loss of Confidentiality
   - Loss of Integrity
   - Loss of Availability
   - Loss of Accountability / Traceability

2. BUSINESS IMPACT FACTORS (Scale 1-9):
   - Financial Damage
   - Reputation Damage
   - Non-compliance
   - Privacy Violation

CRITICAL: Return ONLY a valid JSON object matching this schema:
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
  }}
}}
"""

NUM_RUNS = 5
TEMPERATURE = 0.6

print(f"=== TEST STABILITÀ LLM: 5 RUN (Llama 3.2 3B - Temperatura = {TEMPERATURE}) ===")
print("Avvio delle interrogazioni locali su Ollama in corso...\n")

runs_data = {
    'loss_of_confidentiality': [],
    'loss_of_integrity': [],
    'loss_of_availability': [],
    'loss_of_accountability': [],
    'financial_damage': [],
    'reputation_damage': [],
    'non_compliance': [],
    'privacy_violation': []
}

for i in range(1, NUM_RUNS + 1):
    print(f"--> Esecuzione Run #{i}...", end=" ", flush=True)
    try:
        response = ollama.chat(
            model='llama3.2',
            messages=[{'role': 'user', 'content': PROMPT}],
            format='json',
            options={'temperature': TEMPERATURE}
        )
        content = json.loads(response['message']['content'])
        factors = content.get('owasp_impact_factors', {})
        for k in runs_data.keys():
            val = factors.get(k, 5)
            runs_data[k].append(int(val))
        print("Completato.")
    except Exception as e:
        print(f"Errore: {e}")

print("\n" + "=" * 90)
print(f"{'Fattore di Impatto OWASP':<28} | R1 | R2 | R3 | R4 | R5 |  Media  | Dev. Std | Range")
print("=" * 90)

for factor, vals in runs_data.items():
    if vals:
        mean = sum(vals) / len(vals)
        variance = sum((x - mean) ** 2 for x in vals) / len(vals)
        std_dev = math.sqrt(variance)
        val_range = f"[{min(vals)} - {max(vals)}]"
        runs_str = " | ".join(f" {v} " for v in vals)
        print(f"{factor:<28} | {runs_str} |  {mean:4.2f}   |   {std_dev:4.2f}   | {val_range}")
    else:
        print(f"{factor:<28} | Dati non disponibili")

print("=" * 90)
print("\nTest concluso.")