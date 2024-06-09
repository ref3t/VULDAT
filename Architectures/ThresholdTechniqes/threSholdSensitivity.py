import pandas as pd
import re
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import sys
sys.path.append('VULDAT/Classification/vulDataClass/')
from vulDataClass import VulData
from sentence_transformers import SentenceTransformer

# Logging configuration (replace with your preferred logging library)
import logging

logging.basicConfig(filename='vuln_analysis.log', level=logging.DEBUG)


def true_negative_sum(vul_data_array, cve_ids_a_not_attack, threshold):
  """
  Calculates the number of True Negatives (correctly classified not-vulnerable CVEs)

  Args:
      vul_data_array: List of VulData objects representing CVEs.
      cve_ids_a_not_attack: List of CVE IDs that are not part of attack techniques.
      threshold: Cosine similarity threshold for classifying relevance.

  Returns:
      A tuple containing two counts:
          - True negatives from VULDAT with similarity below threshold and existing in cve_ids_a_not_attack.
          - Not retrieved True negatives (present in cve_ids_a_not_attack but not found in VULDAT).
  """

  count = 0
  for vuldat in vul_data_array:
    if float(vuldat.CVE_Smiliraty) < threshold:
      if vuldat.CVE_ID in cve_ids_a_not_attack:
        count = count + 1
  logging.debug(f"True Negatives (VULDAT, below threshold and in A): {count}")

  count2 = 0
  for item in cve_ids_a_not_attack:
    flag = 0
    for vuldat in vul_data_array:
      if item == vuldat.CVE_ID:
        flag = 1
        break
    if flag == 0:
      count2 = count2 + 1
  logging.debug(f"Not Retrieved True Negatives (In A but not in VULDAT): {count2}")

  return count, count2


def read_tech_with_negative():
  """
  Reads technique data including positive and negative examples from Excel sheets.

  Returns:
      A dictionary where keys are technique IDs and values are lists containing technique description and name.
  """

  file_path_positive = 'VULDAT/Dataset/FinalTechniquesPositive.xlsx'
  file_path_negative = 'VULDAT/Dataset/FinalTechniquesNegative.xlsx'

  logging.info("Reading positive technique data")
  # Read positive data
  data_positive = pd.read_excel(file_path_positive, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
  grouped_data_positive = data_positive.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()
  data_dict_positive = grouped_data_positive.set_index('TechnqiueID').to_dict(orient='index')

  logging.info("Reading negative technique data")
  # Read negative data
  data_negative = pd.read_excel(file_path_negative, header=0, names=['TechnqiueID', 'TechnqiueName', 'TechnqiueDescription'])
  grouped_data_negative = data_negative.groupby('TechnqiueID').agg(lambda x: x.tolist()).reset_index()
  data_dict_negative = grouped_data_negative.set_index('TechnqiueID').to_dict(orient='index')

  # Combine positive and negative data
  data_dict = {**data_dict_positive, **data_dict_negative}

  # Randomly select a subset of negative techniques (optional)
  # random_items = random.sample(list(data_dict.items()), 50)
  # data_dict = dict(random_items)

  logging.info(f"Loaded technique data with {len(data_dict)} techniques (positive and negative)")
  return data_dict


def remove_citations_and_urls(text):
  """
  Removes citations and URLs from text data using regular expressions.

  Args:
      text: The text string to be processed.

  Returns:
      The cleaned text string with citations and URLs removed.
  """

  citation_pattern = r'\(Citation:.*?\)'
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

  # Additional cleaning steps (optional)
  text = re.sub(r"^<code>.*</code>$", "", text, flags=re.MULTILINE)  # Remove code blocks
  text = " ".join(text.split())  # Remove extra spaces
  text = re.sub(r"[^A-Za-z0-9]", " ", text)  # Replace non-alphanumeric characters with spaces

  # text = text.replace("\t", " ")  # Remove tabs (optional)

  return text


def remove_url(text):
  """
  Removes URLs from text data using a regular expression.

  Args:
      text: The text string to be processed.

  Returns:
      The cleaned text string with URLs removed.
  """

  url_pattern = r'(https|http)?:\/\/(\w|\.|\/|\?|\=|\&|\%)*\b'
  logging.debug(f"URL pattern: {url_pattern}")
  text = re.sub(url_pattern, '', text, flags=re.MULTILINE)
  logging.info(f"Removed URLs from text")
  return text


def remove_citation(text):
  """
  Removes citations starting with "(Citation:" from text.

  Args:
      text: The text string to be processed.

  Returns:
      The cleaned text string with citations removed.
  """

  citation_start = text.find('(Citation:')
  if citation_start > 0:
    text = text[:citation_start]
    logging.info(f"Removed citation from text")
  return text


def remove_citations_and_urls2(text):
  """
  Removes citations and URLs from text data using regular expressions.

  Args:
      text: The text string to be processed.

  Returns:
      The cleaned text string with citations and URLs removed.
  """

  text = remove_url(text.copy())  # Operate on a copy to avoid modifying the original
  text = remove_citation(text)
  return text

def removeURLandCitationBulk(texts):
    return [remove_citations_and_urls(text) for text in texts]
def remove_url_and_citation_bulk(texts):
  """
  Applies text cleaning to a list of text strings.

  Args:
      texts: A list of text strings to be cleaned.

  Returns:
      A list of cleaned text strings.
  """

  cleaned_texts = [remove_citations_and_urls(text) for text in texts]
  logging.info(f"Cleaned {len(texts)} texts (removed URLs and citations)")
  return cleaned_texts

df = pd.DataFrame(columns=['Threshold','TechID','TP', 'FP', 'FN', 'TN','AttackTP','AttackTN','AttackFP','AttackFN','CountMapping'])
dfRes = pd.DataFrame(columns=['TechID','Negative','Positive', 'Retrieved by VULDAT', 'Not retrieved by VULDAT','Predicted Positives (>50)','Predicted Negatives (<50)','True Positives (>50)','False Positives (>50)','True Negatives ( <50)','True Negatives (not retrieved)','False Negatives (<50)','False Negatives (not retrieved)','AttackTP','AttackTN','AttackFP','AttackFN'])

def falseNegativeSUMAlltech2222(vul_data_array,CVEsAttack,techniquesID,arrayPositive ,arrayNegative,CvesNotAttack, Threeshold):
    global df
    global dfRes
    global procedure_dict
    countMapping = 0
    MappingCVEsVuldatForAttack = []
    MappingCVEsVuldatNotForAttack = []
    if len(CVEsAttack) > 0:
        for vuldat in vul_data_array:
            # if float(vuldat.CVE_Smiliraty) < smilarityThreshold:
            if vuldat.CVE_ID in CVEsAttack:
                MappingCVEsVuldatForAttack.append(vuldat.CVE_ID)
                countMapping = countMapping +1
        # print("*******************************************total CVEs from VULDAT less 50 And Exist In C***************************************************")
        # print(count)

    MappingCVEsVuldatForAttack = list(set(MappingCVEsVuldatForAttack))
    countMapping = len(MappingCVEsVuldatForAttack)
    logging.info(f"Total CVEs from VULDAT less 50 And Exist In C: {countMapping}")
    
    count = 0
    CVEsVuldatForAttack = []
    CVEsVuldatNotForAttack = []
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) < Threeshold:
            if vuldat.CVE_ID in CVEsAttack:
                CVEsVuldatForAttack.append(vuldat.CVE_ID)
                count = count +1
    # print("*******************************************total CVEs from VULDAT less 50 And Exist In C***************************************************")
    # print(count)
    CVEsVuldatForAttack = list(set(CVEsVuldatForAttack))
    count = len(CVEsVuldatForAttack)
    logging.info(f"Total CVEs from VULDAT less 50 And Exist In C: {count}")


    count2 = 0
    for item in CVEsAttack:
        flag = 0 
        for vuldat in vul_data_array:
            if item == vuldat.CVE_ID:
                flag = 1 
                break
        if flag == 0:
            CVEsVuldatNotForAttack.append(item)
            count2 = count2 +1
    CVEsVuldatNotForAttack = list(set(CVEsVuldatNotForAttack))
    count2 = len(CVEsVuldatNotForAttack)
    logging.info(f"Not In VULDAT But In C: {count2}")
    logging.info(f"FN: {count2+count}")

    # print("*******************************************not In VULDAT But In C ***************************************************")
    # print(count2)

    # print("**********FFFFFFFFFFFFFFFNNNNNNNNNN ***************************************************")
    # print("FN:" + str(count2+count))
    # print("***************************************************")
    PredictedNegatives2 = PredictedNegatives(vul_data_array,Threeshold)
    PredictedPositives2 = PredictedPositives(vul_data_array,Threeshold)
    trueNeativeResless, trueNeativeResNotRetrived  = ResTrueNegatives(vul_data_array, CvesNotAttack,Threeshold)
    AttackTP = 0 
    AttackTN =0 
    AttackFP=0 
    AttackFN =0
    if arrayPositive> 0  and countMapping > 0:
        AttackTP = 1 
    elif ((arrayPositive == 0 and arrayNegative > 0)  and countMapping == 0):
        AttackFP = 1 
    elif arrayPositive == 0  and countMapping > 0:
        AttackFN = 1 
    elif arrayPositive== 0  and countMapping == 0:
        AttackTN = 1 
    logging.info(f"Attack classification for technique {techniquesID}: Attack TP - {AttackTP}, Attack TN - {AttackTN}, Attack FP - {AttackFP}, Attack FN - {AttackFN}")

    df = pd.concat([df, pd.DataFrame({'Threshold':[Threeshold*100],'TechID':[techniquesID],'TP': [arrayPositive], 'FP': [arrayNegative], 'FN': [(count2+count)], 'TN': [(trueNeativeResless+trueNeativeResNotRetrived)], 'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)],'CountMapping':[(countMapping)]})], ignore_index=True)
    dfRes = pd.concat([dfRes, pd.DataFrame({'TechID':[techniquesID],'Negative':[(454-len(CVEsAttack))],
                                    'Positive':[len(CVEsAttack)], 
                                    'Retrieved by VULDAT':[((arrayNegative+arrayPositive)+PredictedNegatives2)], 
                                    'Not retrieved by VULDAT':[((454-len(CVEsAttack))+len(CVEsAttack))-((arrayNegative+arrayPositive)+PredictedNegatives2)],
                                    'Predicted Positives (>50)':[(arrayNegative+arrayPositive)],
                                    'Predicted Negatives (<50)':[PredictedNegatives2],
                                    'True Positives (>50)':[arrayPositive],
                                    'False Positives (>50)':[arrayNegative],
                                    'True Negatives ( <50)':[trueNeativeResless],
                                    'True Negatives (not retrieved)':[trueNeativeResNotRetrived],
                                    'False Negatives (<50)':[count],
                                    'False Negatives (not retrieved)':[count2],
                                        'AttackTP': [(AttackTP)], 'AttackTN': [(AttackTN)], 'AttackFP': [(AttackFP)], 'AttackFN': [(AttackFN)]
                                    })], ignore_index=True)
def ResTrueNegatives(vul_data_array, CvesNotAttack,Threeshold):
    """
    Calculates the number of true negatives (correctly classified not-vulnerable CVEs) based on VULDAT data and a given set of CVEs that are not part of attack techniques.

    Args:
        vul_data_array (list): List of VulData objects representing CVEs.
        CvesNotAttack (list): List of CVE IDs that are not part of attack techniques.
        Threeshold (float): Cosine similarity threshold for classifying relevance.

    Returns:
        tuple: A tuple containing two counts:
            - True negatives from VULDAT with similarity below threshold and existing in CvesNotAttack.
            - Not retrieved true negatives (present in CvesNotAttack but not found in VULDAT).
    """

    return true_negative_sum(vul_data_array,CvesNotAttack,Threeshold)
def PredictedNegatives(vul_data_array, Threeshold):
    """
    Calculates the number of predicted negatives (correctly classified not-vulnerable CVEs) based on VULDAT data and a given similarity threshold.

    Args:
        vul_data_array (list): List of VulData objects representing CVEs.
        Threeshold (float): Cosine similarity threshold for classifying relevance.

    Returns:
        int: The number of predicted negatives.
    """
    count = 0 
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) < Threeshold:
            count = count + 1
    return count
def PredictedPositives(vul_data_array, Threeshold):
    """
    Calculates the number of predicted positives (correctly classified vulnerable CVEs) based on VULDAT data and a given similarity threshold.

    Args:
        vul_data_array (list): List of VulData objects representing CVEs.
        Threeshold (float): Cosine similarity threshold for classifying relevance.

    Returns:
        int: The number of predicted positives.
    """
    count = 0 
    for vuldat in vul_data_array:
        if float(vuldat.CVE_Smiliraty) >= Threeshold:
            count = count + 1
    return count
def main():
    """
    This function checks the similarity between MITRE techniques and VULDAT CVEs using different similarity thresholds.
    It calculates the true negatives and false negatives and outputs the results in an Excel file.
    """
    logging.info("Starting MITRE ATT&CK vs. VULDAT analysis")
    logging.info("Reading data from VULDAT/Dataset/VULDATDataSet.xlsx")
    global df
    global dfRes
    model = SentenceTransformer('sentence-transformers/multi-qa-mpnet-base-dot-v1')
    allLinksFile = "VULDAT/Dataset/VULDATDataSetWithoutProcedures.xlsx"
    print ("Im here1")
    dataCve = pd.read_excel(allLinksFile, sheet_name=0)
    descriptions = dataCve['CVEDescription'].values
    orgDescriptions = dataCve
    dataCve2= dataCve
    print ("Im here2")

    descriptions = removeURLandCitationBulk(descriptions)

    print ("Im here3")
    dataCve['CVEDescription'] = descriptions 
    print ("Im here3")
    descriptions = dataCve['CVEDescription'].values.tolist()
    techniquesName = dataCve['TechnqiueName'].values.tolist()
    # CWEName = dataCve['CAPECName'].values.tolist()
    # CapecDes = dataCve['CAPECDescription'].values.tolist()
    descriptions = descriptions[:len(descriptions)]
    techniquesName = techniquesName[:len(techniquesName)]
    # CWEName = CWEName[:len(CWEName)]
    # joined_list = [ descriptions[i] for i in range(min(len(descriptions), len(techniquesName)))]

    joined_list = [ techniquesName[i]+ " " + descriptions[i] for i in range(min(len(descriptions), len(techniquesName)))]

    sentences = joined_list
    embeddings = model.encode(sentences)
    print ("Im here5")

    techniquesName = dataCve['TechnqiueName'].values.tolist()
    
    logging.info(f"Found {len(descriptions)} descriptions and {len(techniquesName)} technique names")
    techniquesID = dataCve['TechnqiueID'].values.tolist()
    techniquesDes = dataCve['TechnqiueDescription'].values.tolist()
    # capecName = dataCve['CAPECName'].values.tolist()
    # CapecDes = dataCve['CAPECDescription'].values.tolist()
    # CweDes = dataCve['CWE-Description'].values.tolist()
    # CweName = dataCve['CWE-Name'].values.tolist()
    # ProcDesription = dataCve['ATTACK-procedure-description'].values.tolist()
    # ProcIDs = dataCve['ATTACK-Procedure-ID'].values.tolist()

    # tech_dict = readTechData()
    tech_dict = read_tech_with_negative()
    
    for Threeshold in [0.05,0.10,0.15,0.20,0.25,0.30,0.35,0.40,0.45,0.50,0.55,0.60,0.65,0.70,0.75,0.80,0.85,0.90,0.95]:
    # for Threeshold in [0.5,0.55,0.6]:
        countT = 0
        print(str(Threeshold) + "Threshold")
        for key, value in tech_dict.items():
            print(f"ID: {key} ttttt {countT}")
            countT = countT+1
            attack_texts = []
            attack_texts = removeURLandCitationBulk([f"{value['TechnqiueName']} {value['TechnqiueDescription']}"])
            vul_data_array =[]
        
            external_embedding = model.encode(attack_texts[0])
            logging.info(f"Calculating cosine similarities for threshold {Threeshold}")

            # Calculate cosine similarities
            similarities = cosine_similarity(external_embedding.reshape(1, -1), embeddings)[0]

            # Get indices of top 10 closest sentences
            top_10_indices = np.argsort(similarities)[-145000:][::-1]

            # Print top 10 closest sentences
            # orgDescriptions  = dataCve
            finalRes =[]
            array = []
            
            for index in top_10_indices:
                
                if orgDescriptions.loc[index] is not None:
                    if not dataCve.loc[index]['CVEID'] in array:
                        array.append(dataCve.loc[index]['CVEID'])
                        # print(joined_list[index])
                        vul_data = VulData()
                        vul_data.CVE_ID = orgDescriptions.loc[index]['CVEID']
                        vul_data.CVE_Des = orgDescriptions.loc[index]['CVEDescription']
                        # vul_data.CWE_ID = orgDescriptions.loc[index]['CWE-ID']
                        # vul_data.CWE_NAME = orgDescriptions.loc[index]['CWE-Name']
                        # vul_data.CWE_Des = orgDescriptions.loc[index]['CWE-Description']
                        # vul_data.CWE_extended_des = orgDescriptions.loc[index]['CWE-Extended Description']
                        # vul_data.CWE_Detection_Methods = orgDescriptions.loc[index]['CWE-Detection Methods']
                        # vul_data.CWE_Potential_Mitigations = orgDescriptions.loc[index]['CWE-Potential Mitigations']
                        # vul_data.ATTACK_Procedure_ID = orgDescriptions.loc[index]['ATTACK-Procedure-ID']
                        # vul_data.ATTACK_target_ID = orgDescriptions.loc[index]['ATTACK-target ID']
                        # vul_data.ATTACK_techniques_name = orgDescriptions.loc[index]['ATTACK-techniques-name']
                        # vul_data.ATTACK_techniques_descriptionTechniques = orgDescriptions.loc[index]['ATTACK-techniques-descriptionTechniques']
                        # vul_data.ATTACK_procedure_description = orgDescriptions.loc[index]['ATTACK-procedure-description']
                        # vul_data.CAPEC_Name = orgDescriptions.loc[index]['CAPEC-Name']
                        # vul_data.CAPEC_Description = orgDescriptions.loc[index]['CAPEC-Description']
                        # vul_data.CAPEC_Typical_Severity = orgDescriptions.loc[index]['CAPEC-Typical Severity']
                        # vul_data.CAPEC_Execution_Flow = orgDescriptions.loc[index]['CAPEC-Execution Flow']
                        # vul_data.CAPEC_Prerequisites = orgDescriptions.loc[index]['CAPEC-Prerequisites']
                        # vul_data.CAPEC_Skills_Required = orgDescriptions.loc[index]['CAPEC-Skills Required']
                        # vul_data.CAPEC_Resources_Required = orgDescriptions.loc[index]['CAPEC-Resources Required']

                        # vul_data.CAPEC_Mitigations = orgDescriptions.loc[index]['CAPEC-Mitigations']
                        vul_data.CVE_Smiliraty  = f"{similarities[index]:.4f}"
                        # if vul_data._CVE_Smiliraty >= smilarityThreshold:
                        # if float(vul_data.CVE_Smiliraty) > 0.32:
                        finalRes.append(vul_data.CVE_ID + "#" +vul_data.CVE_Des+"#"+vul_data.CVE_Smiliraty )
                        vul_data_array.append(vul_data)
            
            dataCve =dataCve2
            # trainAndTestSet = dataCve.loc[dataCve['TechnqiueID'] == key]
            trainAndTestSet = dataCve[dataCve['TechnqiueID'].str.startswith(key)]
            # trainAndTestSet = dataCve[dataCve['ATTACK-target ID'].str.startswith(techid.split(".")[0])]
            trainAndTestSetCVEs = trainAndTestSet['CVEID']
            trainAndTestSetCVEs2 = trainAndTestSetCVEs.tolist()
            trainAndTestSetCVEs = list(set(trainAndTestSetCVEs2))
            #### not attack
            # CvesNotAttack = dataCve[dataCve['TechnqiueID'] != key]
            CvesNotAttack = dataCve[~dataCve['TechnqiueID'].str.startswith(key)]
            CvesNotAttack = CvesNotAttack['CVEID']
            CvesNotAttack = CvesNotAttack.tolist()
            CvesNotAttack = list(set(CvesNotAttack))
            CvesNotAttack = list(filter(lambda x: x not in trainAndTestSetCVEs, CvesNotAttack))

            arrayPositive = []
            arrayNegative = []
            
            for item in vul_data_array:
                if float(item.CVE_Smiliraty) > Threeshold:
                    flag = 1
                    for cve in trainAndTestSetCVEs:
                        if item.CVE_ID == cve:
                            arrayPositive.append(item.CVE_ID)
                            flag = 0
                            break
                    if flag == 1:
                        arrayNegative.append(item.CVE_ID)
            arrayPositive = list(set(arrayPositive))
            arrayNegative = list(set(arrayNegative))
            logging.info(f"TP: {len(arrayPositive)} FP: {len(arrayNegative)} for technique {key} with threshold {Threeshold}")

            # print("******************************************Tppp****************************************************")
            print("TP:" + str(len(arrayPositive)) + "    FP:"+ str(len(arrayNegative)) +"   " +str(key) + "  "+str(Threeshold))

            falseNegativeSUMAlltech2222(vul_data_array,trainAndTestSetCVEs,key,len(arrayPositive) , len(arrayNegative),CvesNotAttack, Threeshold)
    df.to_excel("VULDAT/Architectures/Results/FinalThreshold59.xlsx", index=False)
    dfRes.to_excel("VULDAT/Architectures/Results/FinalThreshold259.xlsx", index=False)

if __name__ == "__main__":
    main()