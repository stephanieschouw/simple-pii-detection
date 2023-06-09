from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import json
from collections import defaultdict
from math import ceil
import statistics
import tkinter as tk
from tkinter import filedialog

final_json = defaultdict(lambda: defaultdict(dict))
pii_list = []
filename = '1-MB-Test.txt'

# https://microsoft.github.io/presidio/supported_entities/
exclude_list1 = ['UK_NHS','ES_NIF','IT_FISCAL_CODE','IT_DRIVER_LICENSE','IT_VAT_CODE','IT_PASSPORT','IT_IDENTITY_CARD','SG_NRIC_FIN','AU_ABN','AU_ACN','AU_TFN','AU_MEDICARE']
exclude_list2 = ['EMAIL_ADDRESS','LOCATION','NRP','URL','DATE_TIME','PERSON','PHONE_NUMBER']

# Set up analyzer with our updated recognizer registry
registry = RecognizerRegistry()
registry.load_predefined_recognizers()
analyzer = AnalyzerEngine(registry=registry)
anonymizer = AnonymizerEngine()

# Run with input text
f = open(filename,'r')
content = f.read()
clean_text = content.text.encode('utf-8', 'ignore')
text = str(clean_text).replace(r"\r"," ").replace(r"\n"," ").replace(r"\r\n", " ").replace(r"\t"," ").replace(r"\s"," ").replace(r"\f", " ").replace('"', '').replace("  "," ").strip()
f.close()

# Runs block of text and prints first result with analysis
# text="John Smith drivers license is AC432223. Zip code: 10023 and Jane Doe drivers license is DC435623 and Sarah Roberts 134.67.29.79 DoB 8/30/1997 Credit Card Number 378282246310005 and credit card number 378734493671000"
# results = analyzer.analyze(text=text, language="en", return_decision_process=True)
# print(results[0].analysis_explanation)

# To add specific exemptions, see here https://microsoft.github.io/presidio/tutorial/13_allow_list/
results = analyzer.analyze(text=text, language="en")
# print(results)

# Get list of all entities, includes duplicates
entity_list = []
for i in results:
    entity_list.append(i.entity_type)

# Creates dictionary with key = entity and value = # of times entity mentioned
entity_counts = {}
for i in entity_list:
  entity_counts[i] = entity_counts.get(i, 0) + 1

count = 0
first = True
current_entity = []

for i in results:
    
    entity = i.entity_type
    score = i.score
    value = text[i.start:i.end]

    # Gets total # of times entity appears in results
    key_count = entity_counts.get(entity)

    # Excludes non-US entities
    if entity not in exclude_list1:

        # On first iteration of loop when entity not in exclusion list, add entity to tracking list
        if first:
            current_entity.append(entity)
            first = False
        
        # If current entity in dictionary matches the last item in the entity tracking list and loop counter is less than the total number of entities found, record values in dictionary and increment counter
        if entity == current_entity[-1] and count < key_count:
            final_json[entity][count]['text'] = value
            final_json[entity][count]['score'] = ceil(score * 100) / 100.0
            count += 1
        # Add new item to the entity tracking list, reset counter to 0 and record values in dictionary
        else:
            current_entity.append(entity)
            count = 0
            final_json[entity][count]['text'] = value
            final_json[entity][count]['score'] = ceil(score * 100) / 100.0

# Formats defaultdict into JSON
json_object = json.dumps(final_json, indent = 4)
# print(json_object)

# Reformatting defaultdict into normal dictionary
pii_dict = json.loads(json_object)

# Looping through PII dictionary
for k,v in pii_dict.items():
    
    # Creates a list of all scores under an entity
    scores_list = []
    count = 0
    for value in v:
        # text = pii_dict[k][str(count)]['text']
        score = pii_dict[k][str(count)]['score']
        scores_list.append(score)
        count += 1

    # Only set to True when specific entities hit certain threshold (mean of scores list)
    if k not in exclude_list2:
        if k == 'CREDIT_CARD' and statistics.mean(scores_list) > 0.4:
            pii_list.append(True)
        elif k == 'CRYPTO' and statistics.mean(scores_list) >= 0.5:
            pii_list.append(True)
        elif k == 'IBAN_CODE' and statistics.mean(scores_list) >= 0.5:
            pii_list.append(True)
        elif k == 'IP_ADDRESS' and statistics.mean(scores_list) >= 0.5:
            pii_list.append(True)
        elif k == 'MEDICAL_LICENSE' and statistics.mean(scores_list) >= 0.5:
            pii_list.append(True)
        elif k == 'US_BANK_NUMBER' and statistics.mean(scores_list) >= 0.5:
            pii_list.append(True)
        elif k == 'US_DRIVER_LICENSE' and statistics.mean(scores_list) >= 0.5:
            pii_list.append(True)
        elif k == 'US_ITIN' and statistics.mean(scores_list) >= 0.5:
            pii_list.append(True)
        elif k == 'US_PASSPORT' and statistics.mean(scores_list) >= 0.5:
            pii_list.append(True)
        elif k == 'US_SSN' and statistics.mean(scores_list) >= 0.5:
            pii_list.append(True)
        else:
            pii_list.append(False)

# Only set to True when PII present in list
if True in pii_list:
    final_json['PII'] = True
else:
    final_json['PII'] = False

# Reformats defaultdict into JSON
json_object = json.dumps(final_json, indent = 4)
print(json_object)
