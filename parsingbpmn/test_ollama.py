from llm_service import suggest_task_attribute, suggest_data_attributes

# Test 1: Task Attribute Suggestion (Prestito Opere d'Arte)
attrs_task = ["PEC communication", "Mail communication", "Online", "Offline", "Post office communication"]
res_task = suggest_task_attribute("Invio autorizzazione ministeriale", "UserTask", attrs_task)
print("\n--- TEST TASK ---")
print(res_task)

# Test 2: Data Object Attribute Suggestion (Identificazione Richiedente)
res_data = suggest_data_attributes("Documento identità richiedente")
print("\n--- TEST DATA OBJECT ---")
print(res_data)