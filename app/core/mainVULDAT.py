import pandas as pd
import re
from gensim.parsing.preprocessing import preprocess_documents
from sklearn.metrics.pairwise import cosine_similarity
from openpyxl import Workbook
import xlsxwriter
import numpy as np
import itertools
from transformers import AutoTokenizer, AutoModel
from sklearn.metrics.pairwise import cosine_similarity
import torch
from sklearn.feature_extraction.text import TfidfVectorizer
# from core.vulDataClass  import VulData
from vulDataClass  import VulData
from sentence_transformers import SentenceTransformer, util
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer, WordNetLemmatizer
nltk.download('stopwords')
nltk.download('punkt')
nltk.download('wordnet')



def readAllDataCapecAttackCVECWE():
    dfProcedures = pd.read_csv('dfAttackCVEMerged/dfAttackCVEbyCWEMerged3.csv')
    return dfProcedures

def read_cve_file():
    dataCve = pd.read_excel('app/datasets/Vulnerability_Dataset.xlsx', sheet_name=0)
    
    dataCve = dataCve.loc[:, ['CVE-ID', 'DESCRIPTION']]
    return dataCve

# def removeUrls (text):
#     try:
#         text = re.sub(r'(https|http)?:\/\/(\w|\.|\/|\?|\=|\&|\%)*\b', '', text, flags=re.MULTILINE)
#         text = re.sub(r'\b\w*\d+\w*\b', '', text, flags=re.MULTILINE)
#         return(text)
#     except:
#         return text

# def removeURLsFromData(texts):
#     return [removeUrls(text) for text in texts]

def dataPreprocessingCVE(cveData):
    cveDescriptions = cveData['DESCRIPTION'].values
    cveDescriptions = removeURLsFromData(cveDescriptions)
    processed_corpus = preprocess_documents(cveDescriptions)
    list_input = []
    for item in processed_corpus:
        text = ' '.join(item)
        list_input.append(text.strip())
    cveData['DESCRIPTION'] = list_input
    return cveData

def dataPreprocessingCAPECDescription(capecData):
    capecDes = capecData['Description'].values
    capecDes = removeURLsFromData(capecDes)
    processed_corpus = preprocess_documents(capecDes)
    list_input = []
    for item in processed_corpus:
        text = ' '.join(item)
        list_input.append(text.strip())
    capecData['Description'] = list_input
    return capecData

def tfidfCapecDescription(orgcve_description,rowData,cveData):
    input_string = rowData['Description'] 
    input_string = removeUrls(input_string)
    if pd.isnull(input_string):
        return 0, []
    processed_corpus_input = preprocess_documents([input_string])
    list_input = []
    for item in processed_corpus_input:
        text = ' '.join(item)
        list_input.append(text.strip())
    vectorizer = TfidfVectorizer(use_idf=True)
    vectors = vectorizer.fit_transform(cveData['DESCRIPTION'])
    input_tfidf = vectorizer.transform(list_input)
    similarity_scores = cosine_similarity(input_tfidf, vectors)
    closest_paragraph_indices = similarity_scores.argsort()[0][-1:]
    closest_paragraph_probabilities = [similarity_scores[0][index] for index in closest_paragraph_indices]
    for index2, probability in zip(closest_paragraph_indices, closest_paragraph_probabilities):
        return f"{float(probability)*100:.2f}", orgcve_description[index2]
        # print(f"{orgcve_description[index2][0]}###{orgcve_description[index2][1]}###{alldata}###{float(probability)*100:.2f}\n")
        # print (rowData['Description'])
        # print (orgcve_description[index2][1])
        # common_words = (set((rowData['Description']).split())).intersection(set((orgcve_description[index2][1]).split()))
        # print (common_words)



def combinedFeature(orgcve_description,columnArray,rowData,cveData):
    input_string = ''
    for item in columnArray:
        input_string = input_string+str(rowData[item])+" "
    # input_string = rowData['Skills Required'] 
    input_string = removeUrls(input_string)
    if pd.isnull(input_string):
        return 0, []
    processed_corpus_input = preprocess_documents([input_string])
    list_input = []
    for item in processed_corpus_input:
        text = ' '.join(item)
        list_input.append(text.strip())
    vectorizer = TfidfVectorizer(use_idf=True)
    vectors = vectorizer.fit_transform(cveData['DESCRIPTION'])
    input_tfidf = vectorizer.transform(list_input)
    similarity_scores = cosine_similarity(input_tfidf, vectors)
    closest_paragraph_indices = similarity_scores.argsort()[0][-10:]
    closest_paragraph_probabilities = [similarity_scores[0][index] for index in closest_paragraph_indices]
    optionsCVE = []
    for index2, probability in zip(closest_paragraph_indices, closest_paragraph_probabilities):
        optionsCVE.append([f"{float(probability)*100:.2f}", orgcve_description[index2]])
    return optionsCVE

def findMaxSimilarity(orgcve_description,alldata,cveData):
    CVEMergeALLcases = []
    #ATTACK  
    AttackFeatures = ['name', 'descriptionTechniques', 'description'] 
    posAttack = 0
    maxSimalirityAttack = 0
    smiarityCombinOnly = []
    for index,item in enumerate(AttackFeatures):
        smiarityCombinAttack= combinedFeature(orgcve_description,[item],alldata,cveData)
        smiarityCombin = smiarityCombinAttack[9][0]
        if maxSimalirityAttack < float (smiarityCombin):
            maxSimalirityAttack = float(smiarityCombin)
            posAttack = index
            smiarityCombinOnly = smiarityCombinAttack
    # print (smiarityCombinCWECAPECOnly[9])
    smiarityCombinOnly = [row + ['ATTACK:'+str(AttackFeatures[posAttack])] for row in smiarityCombinOnly]

    CVEMergeALLcases.extend(smiarityCombinOnly)





    # #CWE
    # CWEFeatures = ['CWE-NAME']
    # tfidf10CWEDesSimilarity = combinedFeature(orgcve_description,CWEFeatures,alldata,cveData)
    # tfidf10CWEDesSimilarity = [row + ['CWE:'+"CWE-NAME"] for row in tfidf10CWEDesSimilarity]
    # # print (tfidf10CWEDesSimilarity[9])

    # CVEMergeALLcases.extend(tfidf10CWEDesSimilarity)

    # #CAPEC  with CWE 
    # capecFeatures = ['Name','Description','Execution Flow','Prerequisites','Skills Required','Resources Required','Mitigations','Example Instances']
    # combinations = list(itertools.product(CWEFeatures, capecFeatures))
    # combinations = np.array(combinations)
    # # print(combinations)
    # maxCombin = 0
    # pos = 0
    # smiarityCombinCWECAPECMax = []
    # for index,item in enumerate(combinations):
    #     smiarityCombinCWECAPEC = combinedFeature(orgcve_description,item,alldata,cveData)
    #     smiarityCombin = smiarityCombinCWECAPEC[9][0]
    #     if maxCombin < float (smiarityCombin):
    #         maxCombin = float(smiarityCombin)
    #         pos = index
    #         smiarityCombinCWECAPECMax = smiarityCombinCWECAPEC
    # smiarityCombinCWECAPECMax = [row + ['CAPECCWE:'+str(combinations[pos])] for row in smiarityCombinCWECAPECMax]
    # # print (smiarityCombinCWECAPECMax[9])

    # CVEMergeALLcases.extend(smiarityCombinCWECAPECMax)
    # # just CAPEC 
    # capecFeatures = ['Name','Description','Execution Flow','Prerequisites','Skills Required','Resources Required','Mitigations','Example Instances']
    # poscapec = 0
    # maxSimalirityCAPEC = 0
    # smiarityCombinCWECAPECOnly = []
    # for index,item in enumerate(capecFeatures):
    #     smiarityCombinCWECAPEC = combinedFeature(orgcve_description,[item],alldata,cveData)
    #     smiarityCombin = smiarityCombinCWECAPEC[9][0]
    #     if maxSimalirityCAPEC < float (smiarityCombin):
    #         maxSimalirityCAPEC = float(smiarityCombin)
    #         poscapec = index
    #         smiarityCombinCWECAPECOnly = smiarityCombinCWECAPEC
    # # print (smiarityCombinCWECAPECOnly[9])
    # smiarityCombinCWECAPECOnly = [row + ['CAPEC:'+str(capecFeatures[poscapec])] for row in smiarityCombinCWECAPECOnly]

    # CVEMergeALLcases.extend(smiarityCombinCWECAPECOnly)
    CVEMergeALLcases.sort(key=lambda x: x[0], reverse=True)
    # print(CVEMergeALLcases)
    return CVEMergeALLcases



def checkCAPECDesWithCVEsAndFindMaximum():   
    cveDataorg = read_cve_file()
    orgcve_description = cveDataorg.values
    cveData = dataPreprocessingCVE(cveDataorg)
    capecData = readAllDataCapecAttackCVECWE()
    capecData  = capecData.sample(n=50)
    result_df = pd.DataFrame(columns=['Max_TFIDF_Similarity', 'CVE_ID','CVE_Description','MaxSimilarity_By','index','CVE-ID','CVSS-V3','CVSS-V2','SEVERITY','DESCRIPTION','CWE-ID','CWE-NAME','ID_x','target ID','name','descriptionTechniques','description','type','ID_y','Name','Description','Likelihood Of Attack','Typical Severity','Execution Flow','Prerequisites','Skills Required','Resources Required','Indicators','Mitigations','Example Instances','Related Weaknesses','Taxonomy Mappings','ATTACK_techniques_name'])
    capecData = dataPreprocessingCAPECDescription(capecData)
    contrun = 0
    for index, alldata in capecData.iterrows():
        print (contrun +1)
        contrun = contrun + 1
        CVEMergeALLcases = findMaxSimilarity(orgcve_description,alldata,cveData)
        CVEMergeALLcases = [item for item in CVEMergeALLcases if float(item[0]) > smilarityThreshold]
        # print (alldata)
        for ind, data in enumerate(CVEMergeALLcases):
            result_df = pd.concat([result_df, pd.DataFrame({'Max_TFIDF_Similarity': [data[0]], 'CVE_ID':[data[1][0]],'CVE_Description':[data[1][1]],'MaxSimilarity_By':[data[2]],'CVE-ID':alldata['CVE-ID'],'CVSS-V3':alldata['CVSS-V3'],'CVSS-V2':alldata['CVSS-V2'],'SEVERITY':alldata['SEVERITY'],'DESCRIPTION':alldata['DESCRIPTION'],'CWE-ID':alldata['CWE-ID'],'CWE-NAME':alldata['CWE-NAME'],'ID_x':alldata['ID_x'],'target ID':alldata['target ID'],'name':alldata['name'],'descriptionTechniques':alldata['descriptionTechniques'],'description':alldata['description'],'type':alldata['type'],'ID_y':alldata['ID_y'],'Name':alldata['Name'],'Description':alldata['Description'],'Likelihood Of Attack':alldata['Likelihood Of Attack'],'Typical Severity':alldata['Typical Severity'],'Execution Flow':alldata['Execution Flow'],'Prerequisites':alldata['Prerequisites'],'Skills Required':alldata['Skills Required'],'Resources Required':alldata['Resources Required'],'Indicators':alldata['Indicators'],'Mitigations':alldata['Mitigations'],'Example Instances':alldata['Example Instances'],'Related Weaknesses':alldata['Related Weaknesses'],'Taxonomy Mappings':alldata['Taxonomy Mappings'],'ATTACK_techniques_name':alldata['ATTACK_techniques_name']})], ignore_index=True)
    result_df.to_excel('BestResultsCVECWECAPEC.xlsx', index=False)
# import mitreattack.attackToExcel.attackToExcel as attackToExcel
# import mitreattack.attackToExcel.stixToDf as stixToDf



# def findSimilarityBERT():
#     # load pre-trained BERT model and tokenizer
#     model_name = "bert-base-uncased"
#     tokenizer = AutoTokenizer.from_pretrained(model_name)
#     model = AutoModel.from_pretrained(model_name)

#     # define external text and list of descriptions
#     external_text = "create_lazarus_export_tgz.sh in lazarus 0.9.24 allows local users to overwrite or delete arbitrary files via a symlink attack on a (1) /tmp/lazarus.tgz temporary file or a (2) /tmp/lazarus temporary directory."
#     descriptions = ["The feline rested on the rug.", "The dog slept on the couch.", "The bird perched on the branch.", "The fish swam in the pond.", "The horse galloped in the field.", "The cow grazed in the meadow.", "The pig rolled in the mud.", "The sheep bleated in the pen.", "The goat climbed on the rocks.", "The chicken pecked at the ground.", "The duck waddled by the pond."]
#     dataCve = pd.read_excel('app/datasets/Vulnerability_Dataset.xlsx', sheet_name=0)
    
#     dataCve = dataCve.loc[:, ['DESCRIPTION']]
#     descriptions = dataCve['DESCRIPTION'].values.tolist()
#     descriptions = descriptions[:len(descriptions)//110]
#     print(descriptions)
#     # tokenize external text and descriptions
#     external_text_tokens = tokenizer(external_text, return_tensors="pt", padding=True, truncation=True)
#     description_tokens = tokenizer(descriptions, return_tensors="pt", padding=True, truncation=True)

#     # generate BERT embeddings
#     with torch.no_grad():
#         external_text_embedding = model(**external_text_tokens).last_hidden_state[:, 0, :]
#         description_embeddings = model(**description_tokens).last_hidden_state[:, 0, :]

#     # calculate cosine similarity
#     similarity = cosine_similarity(external_text_embedding, description_embeddings)

#     # find 10 descriptions with maximum similarity
#     top_10_indices = similarity[0].argsort()[-10:][::-1]
#     top_10_similarity = similarity[0, top_10_indices]
#     top_10_descriptions = [descriptions[i] for i in top_10_indices]

#     print("Top 10 descriptions with maximum similarity:")
#     for i in range(10):
#         print(f"{i+1}. {top_10_descriptions[i]} (Similarity: {top_10_similarity[i]})")


# import tensorflow_hub as hub
# import numpy as np
# import scipy.spatial
# def findSimilarityUSE():

#     # Load the Universal Sentence Encoder's TF Hub module
#     embed = hub.load("https://tfhub.dev/google/universal-sentence-encoder/4")

#     # Compute the embeddings for the external text and the descriptions
#     external_text = "create_lazarus_export_tgz.sh in lazarus 0.9.24 allows local users to overwrite or delete arbitrary files via a symlink attack on a (1) /tmp/lazarus.tgz temporary file or a (2) /tmp/lazarus temporary directory."
#     dataCve = pd.read_excel('app/datasets/Vulnerability_Dataset.xlsx', sheet_name=0)
#     dataCve = dataCve.loc[:, ['DESCRIPTION']]
#     descriptions = dataCve['DESCRIPTION'].values.tolist()
#     descriptions = descriptions[:len(descriptions)//110]
#     print(descriptions)

#     external_text_embedding = embed([external_text])[0]
#     descriptions_embeddings = embed(descriptions)

#     # Compute the similarity between the external text and the descriptions
#     similarity_scores = np.inner(external_text_embedding, descriptions_embeddings)

#     # Find the indices of the 10 closest descriptions to the external text
#     closest_description_indices = np.argsort(similarity_scores)[-10:]

#     # Print the 10 closest descriptions
#     print("10 closest descriptions:", [descriptions[i] for i in closest_description_indices])


# smilarityThreshold = 50
# findSimilarityUSE()

# checkCAPECDesWithCVEsAndFindMaximum()
from sentence_transformers import SentenceTransformer, util
def checkCVEUsingBert():
    model = SentenceTransformer('all-MiniLM-L6-v2')
    dataCve = pd.read_excel('output.xlsx', sheet_name=0)
    # dataCve = dataCve.loc[:, ['DESCRIPTION']]
    descriptions = dataCve['DESCRIPTION'].values.tolist()
    descriptions = descriptions[:len(descriptions)]
    sentences = descriptions
    # sentences = ["A man is eating a piece of bread.", "perltidy through 20160302, as used by perlcritic, check-all-the-things, and other software, relies on the current working directory for certain output files and does not have a  symlink-attack protection mechanism, which allows local users to overwrite arbitrary files by  creating a symlink, as demonstrated by creating a perltidy.ERR symlink that the victim cannot delete.", 'A DLL Hijacking vulnerability in Eatons 9000x Programming and Configuration Software v 2.0.38 and prior allows an attacker to execute arbitrary code by replacing the required DLLs with malicious DLLs when the software try to load vci11un6.DLL and cinpl.DLL.','A   vulnerability in Eatons 9000x Programming and Configuration Software v 2.0.38 and prior allows an attacker to execute arbitrary code by replacing the required  with malicious when the software try to load vci11un6. and cinpl']
    embeddings = model.encode(sentences)

    # Compare an external sentence with the list of sentences
    attack_texts = ['Adversaries may use [Valid Accounts] to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS). Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the [Accessibility Features] technique for Persistence.',
                    'Adversaries may execute their own malicious payloads by side-loading DLLs. Similar to ,side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order of a program then waiting for the victim application to be invoked,  adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload(s).Side-loading takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other. Adversaries likely use side-loading as a means of masking actions they perform under a legitimate, trusted, and potentially elevated system or software process. Benign executables used to side-load payloads may not be flagged during delivery and/or execution. Adversary payloads may also be encrypted/packed or  otherwise obfuscated until loaded into the memory of the trusted process',
                    'Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.Local Accounts may also be abused to elevate privileges and harvest credentials through [OS Credential Dumping]. Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement. ',
                    'Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping] efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured.Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes. Some methods include:* Hooking API callbacks used for processing keystrokes. Unlike [Credential API Hooking], this focuses solely on API functions intended for processing keystroke data. Reading raw keystroke data from the hardware buffer. Windows Registry modifications. Custom drivers. [Modify System Image]may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions.(Citation: Cisco Blog Legacy Device Attacks)']
    # external_sentence = "Adversaries may execute their own malicious payloads by side-loading DLLs. Similar to ,side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order of a program then waiting for the victim application to be invoked,  adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload(s).Side-loading takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other. Adversaries likely use side-loading as a means of masking actions they perform under a legitimate, trusted, and potentially elevated system or software process. Benign executables used to side-load payloads may not be flagged during delivery and/or execution. Adversary payloads may also be encrypted/packed or  otherwise obfuscated until loaded into the memory of the trusted process"
    result_df = pd.DataFrame(columns=['attack','Max_Similarity','attack_Description','sentence','index','CVE-ID','CVSS-V3','CVSS-V2','SEVERITY','DESCRIPTION','CWE-ID','CWE-NAME','ID_x','target ID','name','descriptionTechniques','description','type','ID_y','Name','Description','Likelihood Of Attack','Typical Severity','Execution Flow','Prerequisites','Skills Required','Resources Required','Indicators','Mitigations','Example Instances','Related Weaknesses','Taxonomy Mappings','ATTACK_techniques_name'])
    contrun = 0
    alldata = dataCve
    for attack in attack_texts:
        external_embedding = model.encode(attack)

        # Calculate cosine similarities
        similarities = cosine_similarity(external_embedding.reshape(1, -1), embeddings)[0]

        # Get indices of top 10 closest sentences
        top_10_indices = np.argsort(similarities)[-100:][::-1]

        # Print top 10 closest sentences
        
        
        for index in top_10_indices:
            print(f"{dataCve.loc[index]}$$$${sentences[index]} (Similarity: {similarities[index]:.4f})")
            print("alldata.loc[index]['CVE-ID'] "+alldata.loc[index]['CVE-ID'])
            print (contrun +1)
            
            result_df = pd.concat([result_df, pd.DataFrame({'attack':[contrun],'Max_Similarity': [similarities[index]],'attack_Description':[attack],'sentence':[{sentences[index]}],'CVE-ID':alldata.loc[index]['CVE-ID'],'CVSS-V3':alldata.loc[index]['CVSS-V3'],'CVSS-V2':alldata.loc[index]['CVSS-V2'],'SEVERITY':alldata.loc[index]['SEVERITY'],'DESCRIPTION':alldata.loc[index]['DESCRIPTION'],'CWE-ID':alldata.loc[index]['CWE-ID'],'CWE-NAME':alldata.loc[index]['CWE-NAME'],'ID_x':alldata.loc[index]['ID_x'],'target ID':alldata.loc[index]['target ID'],'name':alldata.loc[index]['name'],'descriptionTechniques':alldata.loc[index]['descriptionTechniques'],'description':alldata.loc[index]['description'],'type':alldata.loc[index]['type'],'ID_y':alldata.loc[index]['ID_y'],'Name':alldata.loc[index]['Name'],'Description':alldata.loc[index]['Description'],'Likelihood Of Attack':alldata.loc[index]['Likelihood Of Attack'],'Typical Severity':alldata.loc[index]['Typical Severity'],'Execution Flow':alldata.loc[index]['Execution Flow'],'Prerequisites':alldata.loc[index]['Prerequisites'],'Skills Required':alldata.loc[index]['Skills Required'],'Resources Required':alldata.loc[index]['Resources Required'],'Indicators':alldata.loc[index]['Indicators'],'Mitigations':alldata.loc[index]['Mitigations'],'Example Instances':alldata.loc[index]['Example Instances'],'Related Weaknesses':alldata.loc[index]['Related Weaknesses'],'Taxonomy Mappings':alldata.loc[index]['Taxonomy Mappings'],'ATTACK_techniques_name':alldata.loc[index]['ATTACK_techniques_name']})], ignore_index=True)
        contrun = contrun + 1
    result_df.to_excel('BestResultsBERT.xlsx', index=False)


import pandas as pd

def get_severity_and_baseScore(cve_id, data):
    v2_severity = None
    v2_base_score = None
    v3_severity = None
    v3_base_score = None
    for item in data['CVE_Items']:
        if item['cve']['CVE_data_meta']['ID'] == cve_id:
            if 'baseMetricV2' in item['impact']:
                v2_severity = item['impact']['baseMetricV2'].get('severity', None)
                v2_base_score = item['impact']['baseMetricV2']['cvssV2'].get('baseScore', None)
            if 'baseMetricV3' in item['impact']:
                v3_severity = item['impact']['baseMetricV3']['cvssV3'].get('baseSeverity', None)
                v3_base_score = item['impact']['baseMetricV3']['cvssV3'].get('baseScore', None)
            return v2_severity, v2_base_score, v3_severity, v3_base_score
    return None, None, None, None

def mergeCVSS_CVE():
    # Read data from JSON file
    # data  = pd.read_json('finalCVSSJSONS.json', encoding='ISO-8859-1')

    # Read data from Excel file into DataFrame
    df = pd.read_excel('dfAttackCVEbyCWEMerged.xlsx')
    import os
    import json

    directory = 'CVSSJson'
    output_filename = 'finalCVSSJSONS.json'
    files = os.listdir(directory)
    combined_json = {}
    # Create an empty DataFrame to store the results
    results_df = pd.DataFrame()
    for filename in files:
        with open(os.path.join(directory, filename), encoding='utf-8') as f:
            file_json = json.load(f)
            # Calculate the values of severity and baseScore for V2 and V3 for each row in the DataFrame
            temp_df = df.copy()
            temp_df[['v2_severity', 'v2_base_score', 'v3_severity', 'v3_base_score']] = temp_df.apply(lambda row: get_severity_and_baseScore(row['CVE-ID'], file_json), axis=1, result_type='expand')
            # Concatenate the new data with the previous data
            results_df = pd.concat([results_df, temp_df], ignore_index=True)
    # Write the updated DataFrame back to the Excel file
            results_df.to_excel('datarrrr.xlsx', index=False)
    readandremoveemptyCVSS()

def readandremoveemptyCVSS():
    import pandas as pd

    df = pd.read_excel('datarrrr.xlsx')
    df = df.dropna(subset=['v2_severity', 'v2_base_score', 'v3_severity', 'v3_base_score'], how='all')
    df.to_excel('datarrrrnewfile.xlsx', index=False)

# mergeCVSS_CVE()


def mergeCVESSJsonFiles():
    import os
    import json

    directory = 'CVSSJson'
    output_filename = 'finalCVSSJSONS.json'
    files = os.listdir(directory)
    combined_json = {}

    for filename in files:
        with open(os.path.join(directory, filename), encoding='utf-8') as f:
            file_json = json.load(f)
            combined_json.update(file_json)

    with open(output_filename, 'w') as f:
        json.dump(combined_json, f)

# mergeCVESSJsonFiles()

import re

import re

def remove_citations_and_urls(text):
    
    # Regular expression pattern to match citations
    citation_pattern = r'\(Citation:.*?\)'

    # Regular expression pattern to match URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'

    # Find all occurrences of citations in the text
    citations = re.findall(citation_pattern, text)

    # Remove each citation from the text
    for citation in citations:
        text = text.replace(citation, '')

    # Find all occurrences of URLs in the text
    urls = re.findall(url_pattern, text)

    # Remove each URL from the text
    for url in urls:
        text = text.replace(url, '')
    regex = "^<code>.*</code>$"
    text = re.sub(regex, "",text, flags=re.MULTILINE) 
    text = " ".join(text.split()) # remove extra spaces
    text = re.sub("[^A-Za-z0-9]", " ", text) # replace anything that is not alphanumeric with empty string
    # text = text.replace("\t", " ")
    return text

# checkCVEUsingBert()
def removeUrls (text):
    # print (text)
    text = re.sub(r'(https|http)?:\/\/(\w|\.|\/|\?|\=|\&|\%)*\b', '', text, flags=re.MULTILINE)
    text = re.sub(r'(?i)NOTE:.*', '', text)
    # text = re.sub(r'\b\w*\d+\w*\b|\b\w*\.\w*\b', '', text)
    # text = re.sub(r'\.\w+\b', '', text)
    # text = re.sub(r'[^\w\s]', '', text)
    # text = re.sub(r'\b\w*\d+\w*\b', '', text)
    # text = re.sub(r'\s+', ' ', text)
    # text = re.sub(r'\d+', '', text)
    # text = re.sub(r'[,."()]', '', text)
    text = re.sub(r'\b\d+(\.\d+)*\b', '', text) #remove digits 
    # print (text)
    return(text)


def removeCitation(text):
    position = text.find('(Citation:')
    if position > 0:
        return text[:position]
    else:
        return text

def removeURLandCitationBulk(texts):
    return [remove_citations_and_urls(text) for text in texts]
# red = removeURLandCitationBulk(['Untrusted search path vulnerability in  PGP Desktop 9.9.0 Build 397, 9.10.x, 10.0.0 Build 2732,and probably other versions allows local users,and possibly remote attackers,to execute arbitrary code and conduct DLL hijacking attacks via a Trojan horse tsp.dll or tvttsp.dll that is located in the same folder as a .p12,.pem,.pgp,.prk,.prvkr,.pubkr,.rnd or .skr file.'])

def dataPreprocessingStopWords(texts):
    return [preprocess_text_stop_words(text) for text in texts]

def dataPreprocessingStemming(texts):
    return [preprocess_text_stemming(text) for text in texts]

def dataPreprocessingLemmatization(texts):
    return [preprocess_text_lemmatization(text) for text in texts]

def preprocess_text_stop_words(text):
    # Tokenization
    tokens = word_tokenize(text)
    stop_words = set(stopwords.words('english'))

    # Stop words removal
    tokens = [token for token in tokens if token not in stop_words]
        
    return tokens
#Stemming is the process of finding the root of words
def preprocess_text_stemming(text):
    # Tokenization
    tokens = word_tokenize(text)
    stemmer = PorterStemmer()
    # Stemming
    stemmed_tokens = [stemmer.stem(token) for token in tokens]
    
    return stemmed_tokens
#Lemmatization is the process of finding the form of the related word in the dictionary.
def preprocess_text_lemmatization(text):
    # Tokenization
    tokens = word_tokenize(text)
    
    lemmatizer = WordNetLemmatizer()
    # Lemmatization
    lemmatized_tokens = [lemmatizer.lemmatize(token) for token in tokens]
    
    return lemmatized_tokens

df = pd.DataFrame(columns=['TechID','TP', 'FP', 'FN'])

def falseNegativeSUMAlltech2222(vul_data_array,trainAndTestSetCVEs,techniquesID,arrayPositive ,arrayNegative):
    global df
    count = 0
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) < 0.50:
            if vuldat.CVE_ID in trainAndTestSetCVEs:
                count = count +1
    # print("*******************************************total CVEs from VULDAT less 50 And Exist In C***************************************************")
    # print(count)

    count2 = 0
    for item in trainAndTestSetCVEs:
        flag = 0 
        for vuldat in vul_data_array:
            if item == vuldat.CVE_ID:
                flag = 1 
                break
        if flag == 0:
            count2 = count2 +1
    # print("*******************************************not In VULDAT But In C ***************************************************")
    # print(count2)

    # print("**********FFFFFFFFFFFFFFFNNNNNNNNNN ***************************************************")
    print("FN:" + str(count2+count))
    print("***************************************************")
    df = pd.concat([df, pd.DataFrame({'TechID':[techniquesID],'TP': [arrayPositive], 'FP': [arrayNegative], 'FN': [(count2+count)]})], ignore_index=True)

def checkCVEUsingAllTexh():
    global df
    # model = SentenceTransformer('all-MiniLM-L6-v2')
    # model = SentenceTransformer('all-MiniLM-L12-v2')
    model = SentenceTransformer('paraphrase-multilingual-MiniLM-L12-v2')
    # model = SentenceTransformer('all-mpnet-base-v2')
    dataCve = pd.read_excel('output.xlsx', sheet_name=0)
    # dataCve = dataCve.loc[:, ['DESCRIPTION']]
    descriptions = dataCve['CVE-Description'].values
    orgDescriptions = pd.read_excel('output.xlsx', sheet_name=0)
    descriptions = removeURLandCitationBulk(descriptions)
    # descriptions = dataPreprocessingStopWords(descriptions)
    # descriptions = [' '.join(item) for item in descriptions]
    descriptions = dataPreprocessingStemming(descriptions)
    descriptions = [' '.join(item) for item in descriptions]
    # descriptions = dataPreprocessingLemmatization(descriptions)
    # descriptions = [' '.join(item) for item in descriptions]
    dataCve['CVE-Description'] = descriptions
    #remove white space and stop word ... 
    # processed_corpus = preprocess_documents(descriptions)
    # print (text_corpus[1])
    # print ("%%%%%%%$$$$$$$$$$$$$$$$$$$##########################################################")
    # print ( processed_corpus[1])
    # list = []
    # for item in processed_corpus:
    #     text = ' '.join(item)
    #     list.append(text.strip())
    
    # dataCve['CVE-Description'] = list # update the sescription that contains irrelevant words  
    
    descriptions = dataCve['CVE-Description'].values.tolist()
    techniquesName = dataCve['ATTACK-techniques-name'].values.tolist()
    CWEName = dataCve['CAPEC-Name'].values.tolist()
    CapecDes = dataCve['CAPEC-Description'].values.tolist()
    descriptions = descriptions[:len(descriptions)]
    techniquesName = techniquesName[:len(techniquesName)]
    CWEName = CWEName[:len(CWEName)]
    joined_list = [ techniquesName[i]+ " " + descriptions[i] + " " +CWEName[i]  for i in range(min(len(descriptions), len(techniquesName)))]

    sentences = joined_list
    # sentences = ["A man is eating a piece of bread.", "perltidy through 20160302, as used by perlcritic, check-all-the-things, and other software, relies on the current working directory for certain output files and does not have a  symlink-attack protection mechanism, which allows local users to overwrite arbitrary files by  creating a symlink, as demonstrated by creating a perltidy.ERR symlink that the victim cannot delete.", 'A DLL Hijacking vulnerability in Eatons 9000x Programming and Configuration Software v 2.0.38 and prior allows an attacker to execute arbitrary code by replacing the required DLLs with malicious DLLs when the software try to load vci11un6.DLL and cinpl.DLL.','A   vulnerability in Eatons 9000x Programming and Configuration Software v 2.0.38 and prior allows an attacker to execute arbitrary code by replacing the required  with malicious when the software try to load vci11un6. and cinpl']
    embeddings = model.encode(sentences)

    techniquesName = dataCve['ATTACK-techniques-name'].values.tolist()
    techniquesID = dataCve['ATTACK-target ID'].values.tolist()
    techniquesDes = dataCve['ATTACK-techniques-descriptionTechniques'].values.tolist()
    capecName = dataCve['CAPEC-Name'].values.tolist()
    CapecDes = dataCve['CAPEC-Description'].values.tolist()
    CweDes = dataCve['CWE-Description'].values.tolist()
    CweName = dataCve['CWE-Name'].values.tolist()
    ProcDesription = dataCve['ATTACK-procedure-description'].values.tolist()
    ProcIDs = dataCve['ATTACK-Procedure-ID'].values.tolist()


    ####### title /des 
    trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith('T1574')]
    
    cve_ids_C_Attacktech = trainAndTestSet['ATTACK-target ID']
    cve_ids_C_Attacktech = list(cve_ids_C_Attacktech)
    
    ##########
    attack_texts = []
    data_array = [
    "T1547.001", "T1564.003", "T1547.009", "T1574.001", "T1547.005", "T1574.002",
    "T1574.006", "T1564.004", "T1564.001", "T1574.007", "T1547.012", "T1547.004",
    "T1574.008", "T1547.006", "T1564.005", "T1574", "T1574.012", "T1574.004", "T1547.011",
    "T1574.009", "T1547.002", "T1547", "T1547.008", "T1547.013", "T1564.006", "T1547.014",
    "T1574.010", "T1027.002", "T1027", "T1027.005", "T1027.001", "T1027.003", "T1027.004",
    "T1082", "T1592.004", "T1592.002", "T1113", "T1135", "T1125", "T1115", "T1083",
    "T1021.003", "T1550.001", "T1558.001", "T1021.002", "T1021.001", "T1550.002",
    "T1021.005", "T1550.003", "T1133", "T1558.003", "T1550.004", "T1021.004", "T1558.002",
    "T1021", "T1021.006", "T1110", "T1110.002", "T1078", "T1078.002", "T1110.001",
    "T1110.003", "T1078.003", "T1110.004", "T1078.004", "T1552.001", "T1552.005",
    "T1552.004", "T1552.002", "T1552.006", "T1552.003", "T1552", "T1056.001", "T1040",
    "T1056.004", "T1056.002", "T1056", "T1553.002", "T1553.004", "T1553.006", "T1553.001",
    "T1553.005", "T1584.004", "T1550", "T1539", "T1584.006", "T1584.003", "T1584.001",
    "T1499", "T1565.001", "T1565.002", "T1565.003", "T1072", "T1195.002", "T1078.001",
    "T1055.012", "T1055", "T1505.003", "T1055.011", "T1055.001", "T1055.002", "T1055.003",
    "T1055.005", "T1055.013", "T1055.004", "T1505.002", "T1548.002", "T1036", "T1036.005",
    "T1036.003", "T1036.004", "T1036.002", "T1548.003", "T1036.001", "T1548.004"
    ]
    
    # techIDs = []
    # for techid in data_array:
    #     for index, tech in enumerate(techniquesID):  # Use enumerate to get both index and value
    #         attack_text = " " + techniquesName[index] + " "  + " " + techniquesDes[index]  + " " +CweName[index]+" " +capecName[index] +" " + ProcDesription[index]
    #         if not techid in techIDs and techid == tech:
    #             attack_texts.append(attack_text)
    #             techIDs.append(techid)
        
    techIDs = []
    data_array = [
    "T1021",    "T1027",    "T1036",    "T1040",    "T1055",    "T1056",    "T1072",    "T1078",    "T1110",    "T1113",    "T1115",    "T1125",    "T1133",    "T1135",    "T1195.002",    "T1505.002",    "T1505.003",    "T1539",    "T1547",    "T1548.002",    "T1550",    "T1552",    "T1553.001",    "T1558.001",    "T1564.001",    "T1565.001",    "T1574",    "T1584.001",    "T1592.002",    "T1021",    "T1036.003",    "T1055.005",    "T1056.004",    "T1082",    "T1110.003",    "T1499",    "T1552.004",    "T1553.005",    "T1574.008",    "T1547.001"
    ]
    techniquesName2 = dataCve['ATTACK-techniques-name'].drop_duplicates().values.tolist()
    attack_text = " " 
    prcid = ""
    for techid in techniquesName2:
        flag = 0
        for index, tech in enumerate(techniquesName):  # Use enumerate to get both index and value     
            # if not tech  in techIDs:
            if tech == techid:
                if flag == 0:
                    flag = 1 
                    attack_text = " " + techniquesName[index]  
                else:
                    attack_text =attack_text+ "  " + ProcDesription[index]
                             
        attack_texts.append(attack_text)
        techIDs.append(techid)
    print(attack_texts)



    # techniquesName2 = dataCve['ATTACK-techniques-name'].drop_duplicates().values.tolist()
    # attack_text = " " 
    # prcid = ""
    # for techid in techniquesName2:
    #     flag = 0
    #     for index, tech in enumerate(techniquesName):  # Use enumerate to get both index and value     
    #         # if not tech  in techIDs:
    #         if tech == techid:
    #             if flag == 0:
    #                 flag = 1 
    #                 attack_text = " " + techniquesName[index]  + techniquesDes[index]
    #             else:
    #                 attack_text =attack_text+ "  " + techniquesDes[index]
                             
    #     attack_texts.append(attack_text)
    #     techIDs.append(techid)
    # print(attack_texts)

    attack_texts = removeURLandCitationBulk(attack_texts)
    attack_texts = dataPreprocessingStemming(attack_texts)
    attack_texts = [' '.join(item) for item in attack_texts]
    #remove white space and stop word ... 
    # attack_texts = preprocess_documents(attack_texts)
    # list = []
    # for item in attack_texts:
    #     text = ' '.join(item)
    #     list.append(text.strip())

    # attack_texts = list
    contrun = 0
    alldata = dataCve
    count = 0
    vul_data_array =[]
    for attack in attack_texts:
        
        print(techniquesID[count])
        # print(attack)
        external_embedding = model.encode(attack)

        # Compute cosine similarities
        similarities = util.pytorch_cos_sim(external_embedding, embeddings)


        # Calculate cosine similarities
        similarities = cosine_similarity(external_embedding.reshape(1, -1), embeddings)[0]

        # Get indices of top 10 closest sentences
        top_10_indices = np.argsort(similarities)[-4000:][::-1]

        # Print top 10 closest sentences
        # orgDescriptions  = dataCve
        finalRes =[]
        array = []
        smilarityThreshold = 50
        for index in top_10_indices:
            
            if orgDescriptions.loc[index] is not None:
                if not dataCve.loc[index]['CVE-ID'] in array:
                    array.append(dataCve.loc[index]['CVE-ID'])
                    # print(joined_list[index])
                    vul_data = VulData()
                    vul_data.CVE_ID = orgDescriptions.loc[index]['CVE-ID']
                    vul_data.CVE_Des = orgDescriptions.loc[index]['CVE-Description']
                    vul_data.CWE_ID = orgDescriptions.loc[index]['CWE-ID']
                    vul_data.CWE_NAME = orgDescriptions.loc[index]['CWE-Name']
                    vul_data.CWE_Des = orgDescriptions.loc[index]['CWE-Description']
                    vul_data.CWE_extended_des = orgDescriptions.loc[index]['CWE-Extended Description']
                    vul_data.CWE_Detection_Methods = orgDescriptions.loc[index]['CWE-Detection Methods']
                    vul_data.CWE_Potential_Mitigations = orgDescriptions.loc[index]['CWE-Potential Mitigations']
                    vul_data.ATTACK_Procedure_ID = orgDescriptions.loc[index]['ATTACK-Procedure-ID']
                    vul_data.ATTACK_target_ID = orgDescriptions.loc[index]['ATTACK-target ID']
                    vul_data.ATTACK_techniques_name = orgDescriptions.loc[index]['ATTACK-techniques-name']
                    vul_data.ATTACK_techniques_descriptionTechniques = orgDescriptions.loc[index]['ATTACK-techniques-descriptionTechniques']
                    vul_data.ATTACK_procedure_description = orgDescriptions.loc[index]['ATTACK-procedure-description']
                    vul_data.CAPEC_Name = orgDescriptions.loc[index]['CAPEC-Name']
                    vul_data.CAPEC_Description = orgDescriptions.loc[index]['CAPEC-Description']
                    vul_data.CAPEC_Typical_Severity = orgDescriptions.loc[index]['CAPEC-Typical Severity']
                    vul_data.CAPEC_Execution_Flow = orgDescriptions.loc[index]['CAPEC-Execution Flow']
                    vul_data.CAPEC_Prerequisites = orgDescriptions.loc[index]['CAPEC-Prerequisites']
                    vul_data.CAPEC_Skills_Required = orgDescriptions.loc[index]['CAPEC-Skills Required']
                    vul_data.CAPEC_Resources_Required = orgDescriptions.loc[index]['CAPEC-Resources Required']

                    vul_data.CAPEC_Mitigations = orgDescriptions.loc[index]['CAPEC-Mitigations']
                    vul_data.CVE_Smiliraty  = f"{similarities[index]:.4f}"
                    # if vul_data._CVE_Smiliraty >= smilarityThreshold:

                    finalRes.append(vul_data.CVE_ID + "#" +vul_data.CVE_Des+"#"+vul_data.CVE_Smiliraty )
                    vul_data_array.append(vul_data)
                    # print(f"{dataCve.loc[index]}$$$${sentences[index]} (Similarity: {similarities[index]:.4f})")
                    # print(f"{dataCve.loc[index]['CVE-ID']}$$$${sentences[index]} (Similarity: {similarities[index]:.4f})")
                    # print("alldata.loc[index]['CVE-ID'] "+alldata.loc[index]['CVE-ID'])
        print (contrun +1)
            
            # result_df = pd.concat([result_df, pd.DataFrame({'attack':[contrun],'Max_Similarity': [similarities[index]],'attack_Description':[attack],'sentence':[{sentences[index]}],'CVE-ID':alldata.loc[index]['CVE-ID'],'CVSS-V3':alldata.loc[index]['CVSS-V3'],'CVSS-V2':alldata.loc[index]['CVSS-V2'],'SEVERITY':alldata.loc[index]['SEVERITY'],'DESCRIPTION':alldata.loc[index]['DESCRIPTION'],'CWE-ID':alldata.loc[index]['CWE-ID'],'CWE-NAME':alldata.loc[index]['CWE-NAME'],'ID_x':alldata.loc[index]['ID_x'],'target ID':alldata.loc[index]['target ID'],'name':alldata.loc[index]['name'],'descriptionTechniques':alldata.loc[index]['descriptionTechniques'],'description':alldata.loc[index]['description'],'type':alldata.loc[index]['type'],'ID_y':alldata.loc[index]['ID_y'],'Name':alldata.loc[index]['Name'],'Description':alldata.loc[index]['Description'],'Likelihood Of Attack':alldata.loc[index]['Likelihood Of Attack'],'Typical Severity':alldata.loc[index]['Typical Severity'],'Execution Flow':alldata.loc[index]['Execution Flow'],'Prerequisites':alldata.loc[index]['Prerequisites'],'Skills Required':alldata.loc[index]['Skills Required'],'Resources Required':alldata.loc[index]['Resources Required'],'Indicators':alldata.loc[index]['Indicators'],'Mitigations':alldata.loc[index]['Mitigations'],'Example Instances':alldata.loc[index]['Example Instances'],'Related Weaknesses':alldata.loc[index]['Related Weaknesses'],'Taxonomy Mappings':alldata.loc[index]['Taxonomy Mappings'],'ATTACK_techniques_name':alldata.loc[index]['ATTACK_techniques_name']})], ignore_index=True)
        contrun = contrun + 1
        # printVulData(vul_data_array)
            # print(finalRes)
        dataCve = pd.read_excel('output.xlsx', sheet_name=0)
        # trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'] == techniquesID[count]]
        trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith(techniquesID[count])]

        # sub_techniques = ['T1574','T1574.001','T1574.002', 'T1574.003', 'T1574.004', 'T1574.005', 'T1574.006', 'T1574.007', 'T1574.008', 'T1574.009', 'T1574.010', 'T1574.011', 'T1574.012']
        # trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'].isin(sub_techniques)]
        # trainAndTestSet = trainAndTestSet.loc[trainAndTestSet['ATTACK-Procedure-ID'] == 'G0048']
        trainAndTestSetCVEs = trainAndTestSet['CVE-ID']
        arrayPositive = []
        arrayNegative = []
        for item in vul_data_array:
            if float(item.CVE_Smiliraty) > 0.50:
                flag = 1
                for cve in trainAndTestSetCVEs:
                    if item.CVE_ID == cve:
                        arrayPositive.append(item.CVE_ID)
                        flag = 0
                        break
                if flag == 1:
                    arrayNegative.append(item.CVE_ID)
        # print("******************************************Tppp****************************************************")
        print("TP:" + str(len(arrayPositive)) + "    FP:"+ str(len(arrayNegative)) +"   " +techniquesID[count])
        # print(arrayPositive)
        # print("*******************************************FPnnn***************************************************")
        # print(len(arrayNegative))
        # print(arrayNegative)
        # falseNegativeTitleTech(vul_data_array)
        # falseNegativeTitleTechproc(vul_data_array)
        # falseNegativeTitleTechAllproc(vul_data_array)
        # falseNegativeTitleTechAllTech(vul_data_array)
        falseNegativeSUMAlltech2222(vul_data_array,trainAndTestSetCVEs,techniquesID[count],len(arrayPositive) , len(arrayNegative))
        count = count +1
    df.to_excel("finaltechtitleALLproc.xlsx", index=False)
#########################################################################Hijack Execution Flow: DLL Search Order Hijacking Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program. [1][2] Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.There are many ways an adversary can hijack DLL loads. Adversaries may plant trojan dynamic-link library files (DLLs) in a directory that will be searched before the location of a legitimate library that will be requested by a program, causing Windows to load their malicious library when it is called for by the victim program. Adversaries may also perform DLL preloading, also called binary planting attacks, [3] by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program.[4] Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL. [5]Adversaries may also directly modify the search order via DLL redirection, which after being enabled (in the Registry and creation of a redirection file) may cause a program to load a different DLL.[6][7][8]If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program. Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace. has used search order hijacking to force TeamViewer to load a malicious DLL is a cybercriminal group that has been active since at least 2015 and is primarily interested in users of remote banking systems in Russia and neighboring countries. The group uses a Trojan by the same name 
checkCVEUsingAllTexh()
def checkCVEUsingBert2(attackText):
    print("*********--------------------*************")
    print (attackText)
    print("*********--------------------*************")
    # model = SentenceTransformer('all-MiniLM-L6-v2')
    # model = SentenceTransformer('all-MiniLM-L12-v2')
    model = SentenceTransformer('paraphrase-multilingual-MiniLM-L12-v2')
    # model = SentenceTransformer('all-mpnet-base-v2')
    dataCve = pd.read_excel('output.xlsx', sheet_name=0)
    # dataCve = dataCve.loc[:, ['DESCRIPTION']]
    descriptions = dataCve['CVE-Description'].values
    orgDescriptions = pd.read_excel('output.xlsx', sheet_name=0)
    descriptions = removeURLandCitationBulk(descriptions)
    # descriptions = dataPreprocessingStopWords(descriptions)
    # descriptions = [' '.join(item) for item in descriptions]
    descriptions = dataPreprocessingStemming(descriptions)
    descriptions = [' '.join(item) for item in descriptions]
    # descriptions = dataPreprocessingLemmatization(descriptions)
    # descriptions = [' '.join(item) for item in descriptions]
    dataCve['CVE-Description'] = descriptions
    #remove white space and stop word ... 
    # processed_corpus = preprocess_documents(descriptions)
    # print (text_corpus[1])
    # print ("%%%%%%%$$$$$$$$$$$$$$$$$$$##########################################################")
    # print ( processed_corpus[1])
    # list = []
    # for item in processed_corpus:
    #     text = ' '.join(item)
    #     list.append(text.strip())
    
    # dataCve['CVE-Description'] = list # update the sescription that contains irrelevant words  

    descriptions = dataCve['CVE-Description'].values.tolist()
    techniquesName = dataCve['ATTACK-techniques-name'].values.tolist()
    CWEName = dataCve['CAPEC-Name'].values.tolist()
    descriptions = descriptions[:len(descriptions)]
    techniquesName = techniquesName[:len(techniquesName)]
    CWEName = CWEName[:len(CWEName)]
    joined_list = [CWEName[i] + " " + descriptions[i] + " " + techniquesName[i] for i in range(min(len(descriptions), len(techniquesName)))]

    sentences = joined_list
    # sentences = ["A man is eating a piece of bread.", "perltidy through 20160302, as used by perlcritic, check-all-the-things, and other software, relies on the current working directory for certain output files and does not have a  symlink-attack protection mechanism, which allows local users to overwrite arbitrary files by  creating a symlink, as demonstrated by creating a perltidy.ERR symlink that the victim cannot delete.", 'A DLL Hijacking vulnerability in Eatons 9000x Programming and Configuration Software v 2.0.38 and prior allows an attacker to execute arbitrary code by replacing the required DLLs with malicious DLLs when the software try to load vci11un6.DLL and cinpl.DLL.','A   vulnerability in Eatons 9000x Programming and Configuration Software v 2.0.38 and prior allows an attacker to execute arbitrary code by replacing the required  with malicious when the software try to load vci11un6. and cinpl']
    embeddings = model.encode(sentences)

   
    attack_texts = []
    attack_texts.append(attackText)
    
    attack_texts = removeURLandCitationBulk(attack_texts)
    attack_texts = dataPreprocessingStemming(attack_texts)
    attack_texts = [' '.join(item) for item in attack_texts]
    #remove white space and stop word ... 
    # attack_texts = preprocess_documents(attack_texts)
    # list = []
    # for item in attack_texts:
    #     text = ' '.join(item)
    #     list.append(text.strip())

    # attack_texts = list
    contrun = 0
    alldata = dataCve
    vul_data_array =[]
    for attack in attack_texts:
        print(attack)
        external_embedding = model.encode(attack)

        # Compute cosine similarities
        similarities = util.pytorch_cos_sim(external_embedding, embeddings)


        # Calculate cosine similarities
        similarities = cosine_similarity(external_embedding.reshape(1, -1), embeddings)[0]

        # Get indices of top 10 closest sentences
        top_10_indices = np.argsort(similarities)[-30000:][::-1]

        # Print top 10 closest sentences
        # orgDescriptions  = dataCve
        finalRes =[]
        array = []
        smilarityThreshold = 50
        for index in top_10_indices:
            
            if orgDescriptions.loc[index] is not None:
                if not dataCve.loc[index]['CVE-ID'] in array:
                    array.append(dataCve.loc[index]['CVE-ID'])
                    # print(joined_list[index])
                    vul_data = VulData()
                    vul_data.CVE_ID = orgDescriptions.loc[index]['CVE-ID']
                    vul_data.CVE_Des = orgDescriptions.loc[index]['CVE-Description']
                    vul_data.CWE_ID = orgDescriptions.loc[index]['CWE-ID']
                    vul_data.CWE_NAME = orgDescriptions.loc[index]['CWE-Name']
                    vul_data.CWE_Des = orgDescriptions.loc[index]['CWE-Description']
                    vul_data.CWE_extended_des = orgDescriptions.loc[index]['CWE-Extended Description']
                    vul_data.CWE_Detection_Methods = orgDescriptions.loc[index]['CWE-Detection Methods']
                    vul_data.CWE_Potential_Mitigations = orgDescriptions.loc[index]['CWE-Potential Mitigations']
                    vul_data.ATTACK_Procedure_ID = orgDescriptions.loc[index]['ATTACK-Procedure-ID']
                    vul_data.ATTACK_target_ID = orgDescriptions.loc[index]['ATTACK-target ID']
                    vul_data.ATTACK_techniques_name = orgDescriptions.loc[index]['ATTACK-techniques-name']
                    vul_data.ATTACK_techniques_descriptionTechniques = orgDescriptions.loc[index]['ATTACK-techniques-descriptionTechniques']
                    vul_data.ATTACK_procedure_description = orgDescriptions.loc[index]['ATTACK-procedure-description']
                    vul_data.CAPEC_Name = orgDescriptions.loc[index]['CAPEC-Name']
                    vul_data.CAPEC_Description = orgDescriptions.loc[index]['CAPEC-Description']
                    vul_data.CAPEC_Typical_Severity = orgDescriptions.loc[index]['CAPEC-Typical Severity']
                    vul_data.CAPEC_Execution_Flow = orgDescriptions.loc[index]['CAPEC-Execution Flow']
                    vul_data.CAPEC_Prerequisites = orgDescriptions.loc[index]['CAPEC-Prerequisites']
                    vul_data.CAPEC_Skills_Required = orgDescriptions.loc[index]['CAPEC-Skills Required']
                    vul_data.CAPEC_Resources_Required = orgDescriptions.loc[index]['CAPEC-Resources Required']

                    vul_data.CAPEC_Mitigations = orgDescriptions.loc[index]['CAPEC-Mitigations']
                    vul_data.CVE_Smiliraty  = f"{similarities[index]:.4f}"
                    if float(vul_data.CVE_Smiliraty)  >= 0.30:
                        finalRes.append(vul_data.CVE_ID + "#" +vul_data.CVE_Des+"#"+vul_data.CVE_Smiliraty )
                        vul_data_array.append(vul_data)
                    # print(f"{dataCve.loc[index]}$$$${sentences[index]} (Similarity: {similarities[index]:.4f})")
                    # print(f"{dataCve.loc[index]['CVE-ID']}$$$${sentences[index]} (Similarity: {similarities[index]:.4f})")
                    # print("alldata.loc[index]['CVE-ID'] "+alldata.loc[index]['CVE-ID'])
                    print (contrun +1)
            
            # result_df = pd.concat([result_df, pd.DataFrame({'attack':[contrun],'Max_Similarity': [similarities[index]],'attack_Description':[attack],'sentence':[{sentences[index]}],'CVE-ID':alldata.loc[index]['CVE-ID'],'CVSS-V3':alldata.loc[index]['CVSS-V3'],'CVSS-V2':alldata.loc[index]['CVSS-V2'],'SEVERITY':alldata.loc[index]['SEVERITY'],'DESCRIPTION':alldata.loc[index]['DESCRIPTION'],'CWE-ID':alldata.loc[index]['CWE-ID'],'CWE-NAME':alldata.loc[index]['CWE-NAME'],'ID_x':alldata.loc[index]['ID_x'],'target ID':alldata.loc[index]['target ID'],'name':alldata.loc[index]['name'],'descriptionTechniques':alldata.loc[index]['descriptionTechniques'],'description':alldata.loc[index]['description'],'type':alldata.loc[index]['type'],'ID_y':alldata.loc[index]['ID_y'],'Name':alldata.loc[index]['Name'],'Description':alldata.loc[index]['Description'],'Likelihood Of Attack':alldata.loc[index]['Likelihood Of Attack'],'Typical Severity':alldata.loc[index]['Typical Severity'],'Execution Flow':alldata.loc[index]['Execution Flow'],'Prerequisites':alldata.loc[index]['Prerequisites'],'Skills Required':alldata.loc[index]['Skills Required'],'Resources Required':alldata.loc[index]['Resources Required'],'Indicators':alldata.loc[index]['Indicators'],'Mitigations':alldata.loc[index]['Mitigations'],'Example Instances':alldata.loc[index]['Example Instances'],'Related Weaknesses':alldata.loc[index]['Related Weaknesses'],'Taxonomy Mappings':alldata.loc[index]['Taxonomy Mappings'],'ATTACK_techniques_name':alldata.loc[index]['ATTACK_techniques_name']})], ignore_index=True)
        contrun = contrun + 1
    # printVulData(vul_data_array)
        # print(finalRes)
    statisticred(vul_data_array)    
    return vul_data_array
    # result_df.to_excel('BestResultsBERT.xlsx', index=False)


def statisticred(vul_data_array):
    dataCve = pd.read_excel('output.xlsx', sheet_name=0)
    # trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'] == 'T1574']
    # # trainAndTestSet = trainAndTestSet.loc[trainAndTestSet['ATTACK-Procedure-ID'] == 'S0415']
    
    trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'].str.startswith('T1574')]
    # trainAndTestSet = trainAndTestSet.loc[trainAndTestSet['ATTACK-Procedure-ID'] == 'S0415']
    # trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith('T1574')]
    # sub_techniques = ['T1574','T1574.001','T1574.002', 'T1574.003', 'T1574.004', 'T1574.005', 'T1574.006', 'T1574.007', 'T1574.008', 'T1574.009', 'T1574.010', 'T1574.011', 'T1574.012']
    # trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'].isin(sub_techniques)]
    ###### all proc
    # allproc = [
    # "G0027",    "G0045",    "G0048",    "G0096",    "G0107",    "G0120",    "S0009",    "S0070",    "S0109",    "S0113",    "S0134",    "S0153",    "S0182",    "S0194",    "S0260",    "S0280",    "S0363",    "S0373",    "S0415",    "S0458",    "S0530",    "S0538"
    # ]
    # trainAndTestSet = trainAndTestSet.loc[trainAndTestSet['ATTACK-target ID'].isin(allproc)]
    ##############
    # trainAndTestSet = trainAndTestSet.loc[trainAndTestSet['ATTACK-Procedure-ID'] == 'G0048']
    trainAndTestSetCVEs = trainAndTestSet['CVE-ID']
    arrayPositive = []
    arrayNegative = []
    for item in vul_data_array:
        if float(item.CVE_Smiliraty) > 0.50:
            flag = 1
            for cve in trainAndTestSetCVEs:
                if item.CVE_ID == cve:
                    arrayPositive.append(item.CVE_ID)
                    flag = 0
                    break
            if flag == 1:
                arrayNegative.append(item.CVE_ID)
    print("******************************************Tppp****************************************************")
    print(len(arrayPositive))
    # print(arrayPositive)
    print("*******************************************FPnnn***************************************************")
    print(len(arrayNegative))
    # print(arrayNegative)
    falseNegativeTitleTech(vul_data_array)
    # falseNegativeTitleTechproc(vul_data_array)
    # falseNegativeTitleTechAllproc(vul_data_array)
    # falseNegativeTitleTechAllTech(vul_data_array)
    # falseNegativeSUMAlltech(vul_data_array,trainAndTestSetCVEs)


def allTechResults(vul_data_array):
    
    cve_ids_C_Attacktech = ["CVE-2002-0793",
    "CVE-2002-0725",
    "CVE-2001-1043",
    "CVE-1999-0783",
    "CVE-2001-1042",
    "CVE-2000-0342",
    "CVE-2001-1386",
    "CVE-2000-0972",
    "CVE-2001-1494",
    "CVE-2000-1178",
    "CVE-1999-1386",
    "CVE-2003-0844",
    "CVE-2003-0578",
    "CVE-2003-1233",
    "CVE-2003-0517",
    "CVE-2004-1901",
    "CVE-2004-1603",
    "CVE-2004-0689",
    "CVE-2004-0217",
    "CVE-2005-1879",
    "CVE-2005-1880",
    "CVE-2005-0824",
    "CVE-2005-1111",
    "CVE-2005-1916",
    "CVE-2005-0587",
    "CVE-2015-3629",
    "CVE-2020-27833",
    "CVE-2021-21272"
]
   
    falseNegativeSUMAlltech(vul_data_array,cve_ids_C_Attacktech)



def falseNegativeSUMAlltech(vul_data_array,cve_ids_C_Attacktech):
    count = 0
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) < 0.50:
            if vuldat.CVE_ID in cve_ids_C_Attacktech:
                count = count +1
    # print("*******************************************total CVEs from VULDAT less 50 And Exist In C***************************************************")
    # print(count)

    count2 = 0
    for item in cve_ids_C_Attacktech:
        flag = 0 
        for vuldat in vul_data_array:
            if item == vuldat.CVE_ID:
                flag = 1 
                break
        if flag == 0:
            count2 = count2 +1
    # print("*******************************************not In VULDAT But In C ***************************************************")
    # print(count2)

    # print("**********FFFFFFFFFFFFFFFNNNNNNNNNN ***************************************************")
    print("FN:" + (count2+count))
    print("***************************************************")
    # new_row = {'techID': , 'Age': 22}



def falseNegativeTitleTechAllTech(vul_data_array):
    
    dataCve = pd.read_excel('output.xlsx', sheet_name=0)
    
    # trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'] == 'T1574']
    # sub_techniques = ['T1574','T1574.001','T1574.002', 'T1574.003', 'T1574.004', 'T1574.005', 'T1574.006', 'T1574.007', 'T1574.008', 'T1574.009', 'T1574.010', 'T1574.011', 'T1574.012']
    # trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'].isin(sub_techniques)]
    trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith('T1574')]
    cve_ids_C_Attacktech = trainAndTestSet['CVE-ID'].drop_duplicates()
    cve_ids_C_Attacktech = list(cve_ids_C_Attacktech)
    print("Positive")
    # print(cve_ids_C_Attacktech)
    print(len(cve_ids_C_Attacktech))
    # trainAndTestSet = dataCve.loc[~dataCve['ATTACK-target ID'].isin(sub_techniques)]
    trainAndTestSet = dataCve[~dataCve['ATTACK-target ID'].str.startswith('T1574')]
    cve_ids_A_not_attack = trainAndTestSet['CVE-ID'].drop_duplicates()
    
    cve_ids_A_not_attack = list(cve_ids_A_not_attack)
    cve_ids_A_not_attack = list(filter(lambda x: x not in cve_ids_C_Attacktech, cve_ids_A_not_attack))

    print("Negative")
    # print(cve_ids_A_not_attack)
    print(len(cve_ids_A_not_attack))
    

    union_result = set(cve_ids_A_not_attack).union(cve_ids_C_Attacktech)
    union_list = list(union_result)
    print("Union")
    cve_ids_A_C = union_list
    # print(cve_ids_A_C)
    print(len(cve_ids_A_C))
    countLessthan50(vul_data_array)
    notInVULDATButInAorC(vul_data_array,cve_ids_A_C)
    trueNegativeSUM(vul_data_array,cve_ids_A_not_attack)
    falseNegativeSUM(vul_data_array,cve_ids_C_Attacktech)


def falseNegativeTitleTechAllproc(vul_data_array):
    dataCve = pd.read_excel('output.xlsx', sheet_name=0)
    
    trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'] == 'T1574']
    # allproc = [
    # "G0027",    "G0045",    "G0048",    "G0096",    "G0107",    "G0120",    "S0009",    "S0070",    "S0109",    "S0113",    "S0134",    "S0153",    "S0182",    "S0194",    "S0260",    "S0280",    "S0363",    "S0373",    "S0415",    "S0458",    "S0530",    "S0538"
    # ]
    # trainAndTestSet = trainAndTestSet.loc[trainAndTestSet['ATTACK-target ID'].isin(allproc)]
    
    trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith('T1574')]
    cve_ids_C_Attacktech = trainAndTestSet['CVE-ID'].drop_duplicates()
    cve_ids_C_Attacktech = list(cve_ids_C_Attacktech)
    print("Positive")
    # print(cve_ids_C_Attacktech)
    print(len(cve_ids_C_Attacktech))
    trainAndTestSet = dataCve[~dataCve['ATTACK-target ID'].str.startswith('T1574')]
    # trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'] != 'T1574.002']
    # allproc = [
    # "G0027",    "G0045",    "G0048",    "G0096",    "G0107",    "G0120",    "S0009",    "S0070",    "S0109",    "S0113",    "S0134",    "S0153",    "S0182",    "S0194",    "S0260",    "S0280",    "S0363",    "S0373",    "S0415",    "S0458",    "S0530",    "S0538"
    # ]
    # trainAndTestSet = trainAndTestSet.loc[trainAndTestSet['ATTACK-target ID'].isin(allproc)]
    
    cve_ids_A_not_attack = trainAndTestSet['CVE-ID'].drop_duplicates()
    
    cve_ids_A_not_attack = list(cve_ids_A_not_attack)
    cve_ids_A_not_attack = list(filter(lambda x: x not in cve_ids_C_Attacktech, cve_ids_A_not_attack))

    print("Negative")
    # print(cve_ids_A_not_attack)
    print(len(cve_ids_A_not_attack))
    

    union_result = set(cve_ids_A_not_attack).union(cve_ids_C_Attacktech)
    union_list = list(union_result)
    print("Union")
    cve_ids_A_C = union_list
    # print(cve_ids_A_C)
    print(len(cve_ids_A_C))
    countLessthan50(vul_data_array)
    notInVULDATButInAorC(vul_data_array,cve_ids_A_C)
    trueNegativeSUM(vul_data_array,cve_ids_A_not_attack)
    falseNegativeSUM(vul_data_array,cve_ids_C_Attacktech)



def falseNegativeTitleTechproc(vul_data_array):
    dataCve = pd.read_excel('output.xlsx', sheet_name=0)

    trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'] == 'T1574.001']
    trainAndTestSet = trainAndTestSet.loc[trainAndTestSet['ATTACK-Procedure-ID'] == 'S0415']

    # trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith('T1574')]
    cve_ids_C_Attacktech = trainAndTestSet['CVE-ID'].drop_duplicates()
    cve_ids_C_Attacktech = list(cve_ids_C_Attacktech)
    print("Positive")
    # print(cve_ids_C_Attacktech)
    print(len(cve_ids_C_Attacktech))

    trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'] != 'T1574.001']
    # trainAndTestSet = trainAndTestSet.loc[trainAndTestSet['ATTACK-Procedure-ID'] != 'S0415']

    # trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith('T1574')]
    cve_ids_A_not_attack = trainAndTestSet['CVE-ID'].drop_duplicates()
    
    cve_ids_A_not_attack = list(cve_ids_A_not_attack)
    cve_ids_A_not_attack = list(filter(lambda x: x not in cve_ids_C_Attacktech, cve_ids_A_not_attack))

    print("Negative")
    # print(cve_ids_A_not_attack)
    print(len(cve_ids_A_not_attack))
    

    union_result = set(cve_ids_A_not_attack).union(cve_ids_C_Attacktech)
    union_list = list(union_result)
    print("Union")
    cve_ids_A_C = union_list
    # print(cve_ids_A_C)
    print(len(cve_ids_A_C))

    countLessthan50(vul_data_array)
    notInVULDATButInAorC(vul_data_array,cve_ids_A_C)
    trueNegativeSUM(vul_data_array,cve_ids_A_not_attack)
    falseNegativeSUM(vul_data_array,cve_ids_C_Attacktech)


def falseNegativeTitleTech(vul_data_array):
    dataCve = pd.read_excel('output.xlsx', sheet_name=0)

    # trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'] == 'T1574.001']
    trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith('T1574')]
    cve_ids_C_Attacktech = trainAndTestSet['CVE-ID'].drop_duplicates()
    cve_ids_C_Attacktech = list(cve_ids_C_Attacktech)
    print("Positive")
    # print(cve_ids_C_Attacktech)
    print(len(cve_ids_C_Attacktech))

    # trainAndTestSet = dataCve.loc[dataCve['ATTACK-target ID'] != 'T1574.001']
    trainAndTestSet = dataCve[~dataCve['ATTACK-target ID'].str.startswith('T1574')]
    
    # trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith('T1574')]
    cve_ids_A_not_attack = trainAndTestSet['CVE-ID'].drop_duplicates()
    
    cve_ids_A_not_attack = list(cve_ids_A_not_attack)
    cve_ids_A_not_attack = list(filter(lambda x: x not in cve_ids_C_Attacktech, cve_ids_A_not_attack))

    print("Negative")
    # print(cve_ids_A_not_attack)
    print(len(cve_ids_A_not_attack))
    

    union_result = set(cve_ids_A_not_attack).union(cve_ids_C_Attacktech)
    union_list = list(union_result)
    print("Union")
    cve_ids_A_C = union_list
    # print(cve_ids_A_C)
    print(len(cve_ids_A_C))


    # [
    # "CVE-2002-0793", "CVE-2002-0725", "CVE-2001-1494", "CVE-2001-1043", "CVE-1999-0783", "CVE-2001-1042", "CVE-2000-0342", "CVE-2001-1386", "CVE-2000-1178", "CVE-2000-0972", "CVE-1999-1386", "CVE-2003-0844", "CVE-2003-0517", "CVE-2003-0578", "CVE-2003-1233", "CVE-2004-1901", "CVE-2004-1603", "CVE-2004-0689", "CVE-2004-0217", "CVE-2005-1879", "CVE-2005-1880", "CVE-2005-0587", "CVE-2005-1916", "CVE-2005-0824", "CVE-2005-1111", "CVE-2015-3629", "CVE-2020-27833", "CVE-2021-21272", "CVE-2008-5764", "CVE-2008-5748", "CVE-2002-1752", "CVE-2002-1750", "CVE-2002-0495", "CVE-2002-1753", "CVE-2001-1471", "CVE-2003-0395", "CVE-2005-1894", "CVE-2005-3302", "CVE-2005-1527", "CVE-2005-1876", "CVE-2005-1921", "CVE-2005-2498", "CVE-2005-2837", "CVE-2007-1253", "CVE-2008-5305", "CVE-2008-5071", "CVE-2020-8218", "CVE-2021-22204", "CVE-2022-2054", "CVE-2001-1387", "CVE-2002-2094", "CVE-2001-1528", "CVE-2002-0514", "CVE-2002-0515", "CVE-2001-1483", "CVE-2004-2150", "CVE-2004-0294", "CVE-2004-0243", "CVE-2004-0778", "CVE-2004-1428", "CVE-2005-1650", "CVE-2002-0208", "CVE-2004-2252", "CVE-2000-1117", "CVE-2003-0190", "CVE-2003-0637", "CVE-2003-0078", "CVE-2004-1602", "CVE-2005-0918", "CVE-2014-0984", "CVE-2019-10482", "CVE-2001-1551", "CVE-2002-1981", "CVE-2002-1145", "CVE-2002-2042", "CVE-2002-1671", "CVE-2001-1480", "CVE-2000-0315", "CVE-2000-1212", "CVE-2001-1166", "CVE-2002-1154", "CVE-2000-0506", "CVE-2004-0380", "CVE-2004-2204", "CVE-2005-2027", "CVE-2005-1816", "CVE-2005-1742", "CVE-2005-2173", "CVE-2002-1713", "CVE-2002-1711", "CVE-1999-0426", "CVE-2002-1844", "CVE-2001-0497", "CVE-2001-1550", "CVE-2005-1941", "CVE-2005-3435", "CVE-2007-4961", "CVE-2001-0395", "CVE-2001-1291", "CVE-2001-1339", "CVE-1999-1324", "CVE-1999-1152", "CVE-2002-0628", "CVE-2019-0039", "CVE-2001-1536", "CVE-2002-1696", "CVE-2001-1537", "CVE-2002-1800", "CVE-2001-1481", "CVE-2004-2397", "CVE-2005-2160", "CVE-2005-2209", "CVE-2005-1828", "CVE-2007-5778", "CVE-2008-6157", "CVE-2008-6828", "CVE-2008-0174", "CVE-2008-1567", "CVE-2009-1466", "CVE-2009-2272", "CVE-2009-0152", "CVE-2009-1603", "CVE-2009-0964", "CVE-2022-30275", "CVE-2002-1949", "CVE-2004-1852", "CVE-2005-3140", "CVE-2007-4786", "CVE-2007-5626", "CVE-2008-4122", "CVE-2008-4390", "CVE-2008-0374", "CVE-2008-3289", "CVE-2022-30312", "CVE-2022-31204", "CVE-2022-29519", "CVE-2001-1585", "CVE-2005-4900", "CVE-2006-4068", "CVE-2012-6707", "CVE-2017-15999", "CVE-2019-14855", "CVE-2020-25685", "CVE-2022-30320", "CVE-1999-1549", "CVE-2001-1452", "CVE-2000-1218", "CVE-2003-0981", "CVE-2003-0174", "CVE-2005-2188", "CVE-2005-0877", "CVE-2001-0908", "CVE-2004-1950", "CVE-2006-1126", "CVE-2002-0018", "CVE-2006-5462", "CVE-2000-0338", "CVE-2001-0682", "CVE-2002-1914", "CVE-2002-1798", "CVE-2004-2144", "CVE-2004-2257", "CVE-2005-1827", "CVE-2005-1654", "CVE-2005-1668", "CVE-2005-1688", "CVE-2005-1697", "CVE-2005-1698", "CVE-2005-1685", "CVE-2005-1892", "CVE-2022-23607", "CVE-2022-29238", "CVE-2019-1552", "CVE-2000-0102", "CVE-2000-0758", "CVE-2000-0253", "CVE-2000-0101", "CVE-2000-0926", "CVE-2000-0254", "CVE-2000-1234", "CVE-2002-0108", "CVE-2005-2314", "CVE-2005-1784", "CVE-2001-1125", "CVE-2002-0671", "CVE-2008-3438", "CVE-2008-3324", "CVE-2019-9534", "CVE-2021-22909", "CVE-2020-4574", "CVE-2002-1372", "CVE-2007-0897", "CVE-2007-4103", "CVE-2008-2122", "CVE-2009-2858", "CVE-2009-2054", "CVE-2005-3803", "CVE-2005-3716", "CVE-2005-0496", "CVE-2006-7142", "CVE-2008-0961", "CVE-2008-2369", "CVE-2008-1160", "CVE-2010-2073", "CVE-2010-1573", "CVE-2010-2772", "CVE-2012-3503", "CVE-2021-37555", "CVE-2022-30314", "CVE-2022-29953", "CVE-2022-29964", "CVE-2022-30271", "CVE-2022-30997", "CVE-2022-29960", "CVE-2002-1707", "CVE-2002-1704", "CVE-2004-0127", "CVE-2004-0285", "CVE-2004-0068", "CVE-2004-0128", "CVE-2004-0030", "CVE-2005-2157", "CVE-2005-2154", "CVE-2005-2086", "CVE-2005-3335", "CVE-2005-1971", "CVE-2005-1870", "CVE-2005-1864", "CVE-2005-2162", "CVE-2005-1964", "CVE-2005-1869", "CVE-2005-2198", "CVE-2005-1681", "CVE-2010-2076", "CVE-2004-0174", "CVE-2005-3106", "CVE-2006-4342", "CVE-2006-5158", "CVE-2009-2857", "CVE-2009-4272", "CVE-2009-1388", "CVE-2009-1961", "CVE-2009-1283", "CVE-2001-0967", "CVE-2002-1657", "CVE-2005-0408", "CVE-2006-1058", "CVE-2008-4905", "CVE-2008-1526", "CVE-2015-1241", "CVE-2016-2496", "CVE-2017-0492", "CVE-2017-4015", "CVE-2017-5697", "CVE-2017-7440", "CVE-2000-0854", "CVE-2001-0507", "CVE-2002-2040", "CVE-2002-1576", "CVE-2001-0289", "CVE-2001-0943", "CVE-2002-2017", "CVE-1999-1318", "CVE-1999-0690", "CVE-1999-1120", "CVE-1999-1461", "CVE-2001-0942", "CVE-2003-0579", "CVE-2001-0901", "CVE-2002-1841", "CVE-2005-1632", "CVE-2005-1307", "CVE-2005-0254", "CVE-2010-3147", "CVE-2010-3397", "CVE-2010-3152", "CVE-2020-26284", "CVE-2001-0912", "CVE-2022-4826", "CVE-2005-1705", "CVE-2008-2613", "CVE-2008-3485", "CVE-2006-4558", "CVE-2008-1319", "CVE-2010-1795", "CVE-2010-3131", "CVE-2010-3138", "CVE-2010-3402", "CVE-2022-24765", "CVE-2005-1881", "CVE-2006-2428", "CVE-2005-1868", "CVE-2008-1810", "CVE-2004-2262", "CVE-2005-2072", "CVE-2010-3135", "CVE-2005-3288", "CVE-2007-2027", "CVE-2006-6994"
    # ]
    # cve_ids_C_Attacktech = [
    # "CVE-2000-0854", "CVE-2001-0507", "CVE-2001-1386", "CVE-2002-0793", "CVE-2002-2040", "CVE-2002-1576", "CVE-2001-0497", "CVE-2001-1043", "CVE-2002-1844", "CVE-2002-1713", "CVE-2000-0342", "CVE-1999-0426", "CVE-2001-0289", "CVE-2002-1711", "CVE-2001-0943", "CVE-2000-0972", "CVE-1999-1386", "CVE-2002-0725", "CVE-2001-1494", "CVE-2001-1550", "CVE-2002-2017", "CVE-1999-1318", "CVE-1999-0690", "CVE-1999-1120", "CVE-2001-1042", "CVE-1999-1461", "CVE-2001-0942", "CVE-2003-0579", "CVE-2001-0901", "CVE-2004-0217", "CVE-2005-1916", "CVE-2002-1841", "CVE-2005-1632", "CVE-2005-1307", "CVE-2005-0254", "CVE-2010-3147", "CVE-2010-3397", "CVE-2010-3152", "CVE-2019-1552", "CVE-2020-26284", "CVE-2001-0912", "CVE-2022-4826", "CVE-2003-0844", "CVE-2005-1705", "CVE-2005-0587", "CVE-2005-1111", "CVE-2008-5764", "CVE-2008-2613", "CVE-2008-3485", "CVE-2008-5748", "CVE-2020-27833", "CVE-1999-0783", "CVE-2003-1233", "CVE-2004-0689", "CVE-2004-1901", "CVE-2006-4558", "CVE-2008-1319", "CVE-2010-1795", "CVE-2010-3131", "CVE-2010-3138", "CVE-2010-3402", "CVE-2022-24765", "CVE-2000-1178", "CVE-2005-1881", "CVE-2006-2428", "CVE-2003-0517", "CVE-2005-1941", "CVE-2005-1868", "CVE-2008-1810", "CVE-2015-3629", "CVE-2003-0578", "CVE-2004-2262", "CVE-2005-2072", "CVE-2010-3135", "CVE-2021-21272", "CVE-2005-3288", "CVE-2005-0824", "CVE-2007-2027", "CVE-2004-1603", "CVE-2005-1879", "CVE-2005-1880", "CVE-2006-6994"
    # ]
    # cve_ids_A_not_attack = [
    # "CVE-2002-0793", "CVE-2002-0725", "CVE-2001-1494", "CVE-2001-1043", "CVE-1999-0783", "CVE-2001-1042", "CVE-2000-0342", "CVE-2001-1386", "CVE-2000-1178", "CVE-2000-0972", "CVE-1999-1386", "CVE-2003-0844", "CVE-2003-0517", "CVE-2003-0578", "CVE-2003-1233", "CVE-2004-1901", "CVE-2004-1603", "CVE-2004-0689", "CVE-2004-0217", "CVE-2005-1879", "CVE-2005-1880", "CVE-2005-0587", "CVE-2005-1916", "CVE-2005-0824", "CVE-2005-1111", "CVE-2015-3629", "CVE-2020-27833", "CVE-2021-21272", "CVE-2008-5764", "CVE-2008-5748", "CVE-2002-1752", "CVE-2002-1750", "CVE-2002-0495", "CVE-2002-1753", "CVE-2001-1471", "CVE-2003-0395", "CVE-2005-1894", "CVE-2005-3302", "CVE-2005-1527", "CVE-2005-1876", "CVE-2005-1921", "CVE-2005-2498", "CVE-2005-2837", "CVE-2007-1253", "CVE-2008-5305", "CVE-2008-5071", "CVE-2020-8218", "CVE-2021-22204", "CVE-2022-2054", "CVE-2001-1387", "CVE-2002-2094", "CVE-2001-1528", "CVE-2002-0514", "CVE-2002-0515", "CVE-2001-1483", "CVE-2004-2150", "CVE-2004-0294", "CVE-2004-0243", "CVE-2004-0778", "CVE-2004-1428", "CVE-2005-1650", "CVE-2002-0208", "CVE-2004-2252", "CVE-2000-1117", "CVE-2003-0190", "CVE-2003-0637", "CVE-2003-0078", "CVE-2004-1602", "CVE-2005-0918", "CVE-2014-0984", "CVE-2019-10482", "CVE-2001-1551", "CVE-2002-1981", "CVE-2002-1145", "CVE-2002-2042", "CVE-2002-1671", "CVE-2001-1480", "CVE-2000-0315", "CVE-2000-1212", "CVE-2001-1166", "CVE-2002-1154", "CVE-2000-0506", "CVE-2004-0380", "CVE-2004-2204", "CVE-2005-2027", "CVE-2005-1816", "CVE-2005-1742", "CVE-2005-2173", "CVE-2002-1713", "CVE-2002-1711", "CVE-1999-0426", "CVE-2002-1844", "CVE-2001-0497", "CVE-2001-1550", "CVE-2005-1941", "CVE-2005-3435", "CVE-2007-4961", "CVE-2001-0395", "CVE-2001-1291", "CVE-2001-1339", "CVE-1999-1324", "CVE-1999-1152", "CVE-2002-0628", "CVE-2019-0039", "CVE-2001-1536", "CVE-2002-1696", "CVE-2001-1537", "CVE-2002-1800", "CVE-2001-1481", "CVE-2004-2397", "CVE-2005-2160", "CVE-2005-2209", "CVE-2005-1828", "CVE-2007-5778", "CVE-2008-6157", "CVE-2008-6828", "CVE-2008-0174", "CVE-2008-1567", "CVE-2009-1466", "CVE-2009-2272", "CVE-2009-0152", "CVE-2009-1603", "CVE-2009-0964", "CVE-2022-30275", "CVE-2002-1949", "CVE-2004-1852", "CVE-2005-3140", "CVE-2007-4786", "CVE-2007-5626", "CVE-2008-4122", "CVE-2008-4390", "CVE-2008-0374", "CVE-2008-3289", "CVE-2022-30312", "CVE-2022-31204", "CVE-2022-29519", "CVE-2001-1585", "CVE-2005-4900", "CVE-2006-4068", "CVE-2012-6707", "CVE-2017-15999", "CVE-2019-14855", "CVE-2020-25685", "CVE-2022-30320", "CVE-1999-1549", "CVE-2001-1452", "CVE-2000-1218", "CVE-2003-0981", "CVE-2003-0174", "CVE-2005-2188", "CVE-2005-0877", "CVE-2001-0908", "CVE-2004-1950", "CVE-2006-1126", "CVE-2002-0018", "CVE-2006-5462", "CVE-2000-0338", "CVE-2001-0682", "CVE-2002-1914", "CVE-2002-1798", "CVE-2004-2144", "CVE-2004-2257", "CVE-2005-1827", "CVE-2005-1654", "CVE-2005-1668", "CVE-2005-1688", "CVE-2005-1697", "CVE-2005-1698", "CVE-2005-1685", "CVE-2005-1892", "CVE-2022-23607", "CVE-2022-29238", "CVE-2019-1552", "CVE-2000-0102", "CVE-2000-0758", "CVE-2000-0253", "CVE-2000-0101", "CVE-2000-0926", "CVE-2000-0254", "CVE-2000-1234", "CVE-2002-0108", "CVE-2005-2314", "CVE-2005-1784", "CVE-2001-1125", "CVE-2002-0671", "CVE-2008-3438", "CVE-2008-3324", "CVE-2019-9534", "CVE-2021-22909", "CVE-2020-4574", "CVE-2002-1372", "CVE-2007-0897", "CVE-2007-4103", "CVE-2008-2122", "CVE-2009-2858", "CVE-2009-2054", "CVE-2005-3803", "CVE-2005-3716", "CVE-2005-0496", "CVE-2006-7142", "CVE-2008-0961", "CVE-2008-2369", "CVE-2008-1160", "CVE-2010-2073", "CVE-2010-1573", "CVE-2010-2772", "CVE-2012-3503", "CVE-2021-37555", "CVE-2022-30314", "CVE-2022-29953", "CVE-2022-29964", "CVE-2022-30271", "CVE-2022-30997", "CVE-2022-29960", "CVE-2002-1707", "CVE-2002-1704", "CVE-2004-0127", "CVE-2004-0285", "CVE-2004-0068", "CVE-2004-0128", "CVE-2004-0030", "CVE-2005-2157", "CVE-2005-2154", "CVE-2005-2086", "CVE-2005-3335", "CVE-2005-1971", "CVE-2005-1870", "CVE-2005-1864", "CVE-2005-2162", "CVE-2005-1964", "CVE-2005-1869", "CVE-2005-2198", "CVE-2005-1681", "CVE-2010-2076", "CVE-2004-0174", "CVE-2005-3106", "CVE-2006-4342", "CVE-2006-5158", "CVE-2009-2857", "CVE-2009-4272", "CVE-2009-1388", "CVE-2009-1961", "CVE-2009-1283", "CVE-2001-0967", "CVE-2002-1657", "CVE-2005-0408", "CVE-2006-1058", "CVE-2008-4905", "CVE-2008-1526", "CVE-2015-1241", "CVE-2016-2496", "CVE-2017-0492", "CVE-2017-4015", "CVE-2017-5697", "CVE-2017-7440"
    # ]

    countLessthan50(vul_data_array)
    notInVULDATButInAorC(vul_data_array,cve_ids_A_C)
    trueNegativeSUM(vul_data_array,cve_ids_A_not_attack)
    falseNegativeSUM(vul_data_array,cve_ids_C_Attacktech)

def falseNegativeSUM(vul_data_array,cve_ids_C_Attacktech):
    count = 0
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) < 0.50:
            if vuldat.CVE_ID in cve_ids_C_Attacktech:
                count = count +1
    print("*******************************************total CVEs from VULDAT less 50 And Exist In C***************************************************")
    print(count)

    count2 = 0
    for item in cve_ids_C_Attacktech:
        flag = 0 
        for vuldat in vul_data_array:
            if item == vuldat.CVE_ID:
                flag = 1 
                break
        if flag == 0:
            count2 = count2 +1
    print("*******************************************not In VULDAT But In C ***************************************************")
    print(count2)

    print("**********FFFFFFFFFFFFFFFNNNNNNNNNN ***************************************************")
    print((count2+count))



def trueNegativeSUM(vul_data_array,cve_ids_A_not_attack):
    count = 0
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) < 0.50:
            if vuldat.CVE_ID in cve_ids_A_not_attack:
                count = count +1
    print("*******************************************total CVEs from VULDAT less 50 And Exist In A***************************************************")
    print(count)

    count2 = 0
    for item in cve_ids_A_not_attack:
        flag = 0 
        for vuldat in vul_data_array:
            if item == vuldat.CVE_ID:
                flag = 1 
                break
        if flag == 0:
            count2 = count2 +1
    print("*******************************************not In VULDAT But In A ***************************************************")
    print(count2)

    print("**********TTTTTTTTNNNNNNNNNN ***************************************************")
    print((count2+count))


def notInVULDATButInAorC(vul_data_array,cve_ids_A_C):
    count = 0
    for item in cve_ids_A_C:
        flag = 0 
        for vuldat in vul_data_array:
            if item == vuldat.CVE_ID:
                flag = 1 
                break
        if flag == 0:
            count = count +1
    print("*******************************************not In VULDAT But In A or C***************************************************")
    print(count)




def countLessthan50(vul_data_array):
    count = 0
    for item in vul_data_array:
        if float(item.CVE_Smiliraty) < 0.50:
            count = count + 1
    print("*******************************************Count less than 50***************************************************")
    print(count)

def printVulData(vul_data_array):
    # Iterate over the VulData objects in the array and print the data
    for vul_data in vul_data_array:
        print("CVE ID:", vul_data.CVE_ID)
        print("CVE Description:", vul_data.CVE_Des)
        print("CWE:", vul_data.CWE_ID)
        print("CWE Name:", vul_data.CWE_NAME)
        print("CWE Description:", vul_data.CWE_Des)
        print("CWE Extended Description:", vul_data.CWE_extended_des)
        print("CWE Detection Methods:", vul_data.CWE_Detection_Methods)
        print("CWE Potential Mitigations:", vul_data.CWE_Potential_Mitigations)
        print("ATTACK Procedure ID:", vul_data.ATTACK_Procedure_ID)
        print("ATTACK Target ID:", vul_data.ATTACK_target_ID)
        print("ATTACK Techniques Name:", vul_data.ATTACK_techniques_name)
        print("ATTACK Techniques Description:", vul_data.ATTACK_techniques_descriptionTechniques)
        print("ATTACK Procedure Description:", vul_data.ATTACK_procedure_description)
        print("CAPEC Name:", vul_data.CAPEC_Name)
        print("CAPEC Description:", vul_data.CAPEC_Description)
        print("CAPEC Typical Severity:", vul_data.CAPEC_Typical_Severity)
        print("CAPEC Execution Flow:", vul_data.CAPEC_Execution_Flow)
        print("CAPEC Prerequisites:", vul_data.CAPEC_Prerequisites)
        print("CAPEC Skills Required:", vul_data.CAPEC_Skills_Required)
        print("CAPEC Resources Required:", vul_data.CAPEC_Resources_Required)
        print("CAPEC Mitigations:", vul_data.CAPEC_Mitigations)
        print("------------------------")


def getCveData(vulInfo, cveId):
    print(cveId)
    for row in vulInfo:
        if cveId in row.CVE_ID:
            return row


def getCVEsUsingMiniLMModel(attackText):
    model = SentenceTransformer('all-MiniLM-L6-v2')
    dataCve = pd.read_excel('CVEsDataset.xlsx', sheet_name=0)
    descriptions = dataCve['CVE-Description'].values.tolist()
    descriptions = descriptions[:len(descriptions)]
    embeddings = model.encode(descriptions)
    attackText = removeUrls(attackText)
    vul_data_array =[]
    external_embedding = model.encode(attackText)
    similarities = cosine_similarity(external_embedding.reshape(1, -1), embeddings)[0]
    top_10_indices = np.argsort(similarities)[-100:][::-1]   
    CVEsArray = []
    for index in top_10_indices:
        if dataCve.loc[index] is not None:
            if not dataCve.loc[index]['CVE-ID'] in CVEsArray:
                CVEsArray.append(dataCve.loc[index]['CVE-ID'])
                vul_data_array.append(dataCve.loc[index])
    return vul_data_array




# checkCVEUsingBert2('Hijack Execution Flow	Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program. (Citation: Microsoft Dynamic Link Library Search Order)(Citation: FireEye Hijacking July 2010) Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution. There are many ways an adversary can hijack DLL loads Adversaries may plant trojan dynamic-link library files (DLLs) in a directory that will be searched before the location of a legitimate library that will be requested by a program causing Windows to load their malicious library when it is called for by the victim program. Adversaries may also perform DLL preloading, also called binary planting attacks, (Citation: OWASP Binary Planting) by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program.(Citation: FireEye fxsst June 2011) Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL. (Citation: Microsoft Security Advisory 2269637) Adversaries may also directly modify the search order via DLL redirection, which after being enabled (in the Registry and creation of a redirection file) may cause a program to load a different DLL.(Citation: Microsoft Dynamic-Link Library Redirection)(Citation: Microsoft Manifests)(Citation: FireEye DLL Search Order Hijacking) If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program. Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace ')
