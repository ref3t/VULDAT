import pandas as pd
import re
from gensim.parsing.preprocessing import preprocess_documents
from sklearn.metrics.pairwise import cosine_similarity
from openpyxl import Workbook

from sklearn.feature_extraction.text import TfidfVectorizer

def removeUrls (text):
    text = re.sub(r'(https|http)?:\/\/(\w|\.|\/|\?|\=|\&|\%)*\b', '', text, flags=re.MULTILINE)
    text = re.sub(r'\b\w*\d+\w*\b', '', text, flags=re.MULTILINE)
    return(text)
def removeURLsFromData(texts):
    return [removeUrls(text) for text in texts]
def getDescription(generalDes):

    dataCve = pd.read_excel('app/datasets/Vulnerability_Dataset.xlsx', sheet_name=0)
    
    dataCve = dataCve.loc[:, ['CVE-ID', 'DESCRIPTION', 'CWE-ID', 'CWE-NAME']]
    
    trainAndTestSet = dataCve
    dataframe2 = pd.concat([trainAndTestSet], ignore_index=True)
    test = dataframe2.loc[:, ['CVE-ID', 'DESCRIPTION', 'CWE-ID', 'CWE-NAME']]
    trainAndTestSet = test
    org_TTP_description = trainAndTestSet.values

    text_corpus = trainAndTestSet['DESCRIPTION'].values
    text_corpus = removeURLsFromData(text_corpus)
    #############################################################################
    processed_corpus = preprocess_documents(text_corpus)
    list = []
    for item in processed_corpus:
        text = ' '.join(item)
        list.append(text.strip())
    trainAndTestSet['DESCRIPTION'] = list

    text_corpus_input = removeUrls(generalDes)
    #############################################################################
    processed_corpus_input = preprocess_documents([text_corpus_input])

    list_input = []
    for item in processed_corpus_input:
        text = ' '.join(item)
        list_input.append(text.strip())
    genDes = list_input
    

    vectorizer = TfidfVectorizer(use_idf=True)
    vectors = vectorizer.fit_transform(trainAndTestSet['DESCRIPTION'])
    input_tfidf = vectorizer.transform(genDes)
    similarity_scores = cosine_similarity(input_tfidf, vectors)
   
    closest_index = similarity_scores.argmax()

    closest_string = org_TTP_description[closest_index]
  
    closest_paragraph_indices = similarity_scores.argsort()[0][-1:]
    closest_paragraph_probabilities = [similarity_scores[0][index] for index in closest_paragraph_indices]
    for index2, probability in zip(closest_paragraph_indices, closest_paragraph_probabilities):
        # ###{org_TTP_description['CWE-ID']}###{org_TTP_description['CWE-NAME']}
        # print(f"{closest_string[0]}###{closest_string[1]}###{org_TTP_description['CVE-ID']}###{org_TTP_description['DESCRIPTION']}###{float(probability)*100:.2f}\n")
        print(f"{closest_string[0]}###{closest_string[1]}####{closest_string[2]}###{closest_string[3]}###{float(probability)*100:.2f}")
        return closest_string,f"{float(probability)*100:.2f}"


def getAllCweRelated(cweID):
    dataCve = pd.read_excel('app/datasets/Vulnerability_Dataset.xlsx', sheet_name=0)
    
    dataCve = dataCve.loc[:, ['CVE-ID', 'DESCRIPTION', 'CWE-ID', 'CWE-NAME']]
    grouped_data = dataCve[dataCve['CWE-ID'] == cweID]
    # print(grouped_data)
    # for index, row in grouped_data.iterrows():
    #     print (row['CWE-ID'])
    return grouped_data




###########################################MAAAAAAPING 
def splitData(dataFrame, nameofcol):
    # Create an empty dataframe to store the expanded rows
    expanded_df = pd.DataFrame()
    # Split the 'Name' column into a list of names and append the rows
    for index, rowr in dataFrame.iterrows():
        # print (rowr['Related Weaknesses'])
        weaks = str(rowr[nameofcol]).split('::')    
        for weak in weaks:
            if len (weak) > 0:
                new_row = rowr.copy()
                new_row[nameofcol] = weak
                expanded_df = expanded_df._append(new_row, ignore_index=True)
    return expanded_df
    
def splitDataATTACKtechniques(dataFrame):
    # Create an empty dataframe to store the expanded rows
    expanded_df = pd.DataFrame()
    dataFrame['ATTACK_techniques_name'] = ''
    # Split the 'Name' column into a list of names and append the rows
    for index, rowr in dataFrame.iterrows():
        # print (rowr['Related Weaknesses'])
        weaks = str(rowr['Taxonomy Mappings']).split('::')
        for weak in weaks:
            if len (weak) > 0:
                match = re.search(r'ENTRY NAME:(.*?)(:|''$)', weak)
                if match:
                    entry_name = match.group(1).strip()
                    dataFrame.at[index,'ATTACK_techniques_name']= entry_name
                
    return dataFrame
    


def mapCapecFilter():
    dataCapec = pd.read_excel('app/datasets/CAPEC.xlsx', sheet_name=0)
    
    dataCapec = dataCapec.loc[:, ['ID', 'Name', 'Description', 'Likelihood Of Attack', 'Typical Severity', 'Execution Flow', 'Prerequisites','Skills Required', 'Resources Required', 'Indicators', 'Mitigations', 'Example Instances', 'Related Weaknesses', 'Taxonomy Mappings']]
    newData = splitData(dataCapec, 'Related Weaknesses')
    newData = splitDataATTACKtechniques(newData)
    newData.to_excel('CAPECWithCwesData.xlsx', index=False)
    # num_data_points = newData['Related Weaknesses'].nunique() # 337
    # print(num_data_points)
    dataCapec = pd.read_excel('CAPECWithCwesData.xlsx', sheet_name=0)
    print(dataCapec.head(50))
    return

def splitTechniqueName(text):
    return text.split(':')[0]

def mapAttackCAPEC():
    
    dfTactics = pd.read_excel('app/datasets/attack-data.xlsx', sheet_name=0)
    dfTechniques = pd.read_excel('app/datasets/attack-data.xlsx', sheet_name=2)
    dfProcedures = pd.read_excel('app/datasets/attack-data.xlsx', sheet_name=3)

    dfTacticsCut = dfTactics.loc[:, ['ID', 'name', 'description']]
    dfTacticsCut['type'] = 'tactics'
   
    dfTechniquesCut = dfTechniques.loc[:, ['ID', 'name', 'description']]
    dfTechniquesCut['type'] = 'techniques'

    dfTechniqueProcedureMerged = pd.merge(dfTechniques, dfProcedures, left_on='ID', right_on='target ID')

    dfProceduresCut = dfTechniqueProcedureMerged.loc[:, ['source ID', 'target ID', 'name','description', 'mapping description']]
    
    dfProceduresCut['ID'] = dfProceduresCut['source ID']
    dfProceduresCut['descriptionTechniques'] = dfProceduresCut['description']
    dfProceduresCut['description'] = dfProceduresCut['mapping description']
    dfProceduresCut['type'] = 'example'
    dfProceduresCut = dfProceduresCut.loc[:, ['ID',  'target ID', 'name', 'descriptionTechniques','description', 'type']]

    dataframe = pd.concat([dfTacticsCut, dfTechniquesCut, dfProceduresCut], ignore_index=True)
    
    trainAndTestSet = dataframe.loc[dataframe['type'] == 'example']
    trainAndTestSet['name'] = trainAndTestSet['name'].apply(splitTechniqueName) #Abuse Elevation Control Mechanism: Bypass User Account Control
    
    dataframe2 = pd.concat([trainAndTestSet], ignore_index=True)
    test = dataframe2.loc[:, ['ID', 'target ID', 'name', 'descriptionTechniques','description', 'type']]
    trainAndTestSet = test
    print(test.head(10))
    
    dataCapec = pd.read_excel('CAPECWithCwesData.xlsx', sheet_name=0)
    dfAttackcapecMerged = pd.merge(trainAndTestSet, dataCapec, left_on='name', right_on='CAPEC-ATTACK_techniques_name')
    print(dfAttackcapecMerged.head(10))
    dfAttackcapecMerged.to_excel('dfAttackcapecMerged.xlsx', index=False)
    return


def mapattackcapeccvebycwe():
    dataattack = pd.read_excel('dfAttackcapecMerged.xlsx', sheet_name=0)
    datacve = pd.read_excel('FinalCVEsCWEs.xlsx', sheet_name=0)
    dataattack['CAPEC-Related Weaknesses'] = dataattack['CAPEC-Related Weaknesses'].astype(str).str.rstrip('.0')
    # dataattack['CAPEC-Related Weaknesses'] = dataattack['CAPEC-Related Weaknesses'].apply(lambda x: 'CWE-' + str(x))
    datacve['CWE-ID'] = datacve['CWE-ID'].astype(str)
    dataattack['CAPEC-Related Weaknesses'] = dataattack['CAPEC-Related Weaknesses'].astype(str)
    dfAttackcapecMerged = pd.merge(datacve, dataattack, left_on='CWE-ID', right_on='CAPEC-Related Weaknesses')
    # common_values = set(datacve['CWE-ID']).intersection(set(dataattack['CAPEC-Related Weaknesses']))
    # print(f'Number of common values: {len(common_values)}')
    dfAttackcapecMerged = dfAttackcapecMerged.sample(n=10000)

    # print(dfAttackcapecMerged.head(10))
    # dfAttackcapecMerged.to_csv('dfAttackCVEbyCWEMerged.csv.gz', index=False, compression='gzip')
    dfAttackcapecMerged.head(100000).to_excel('output.xlsx', index=False)
    dfAttackcapecMerged.to_excel('dfAttackCVEbyCWEMerged.xlsx', index=False)
  
def addCveInfoAfterExportCvefromCWE():
    cvecwe = pd.read_excel('CVEsCWEs.xlsx', sheet_name=0)
    datacve = pd.read_csv('cvesjust.csv', encoding='latin-1')
    dfAttackcapecMerged = pd.merge(datacve, cvecwe, left_on='CVE-ID', right_on='CVE-ID')

    dfAttackcapecMerged.to_excel('FinalCVEsCWEs.xlsx', index=False)
    
    
def mapcvebyCAPECUsingCWE():
    dataattack = pd.read_excel('dfAttackcapecMerged.xlsx', sheet_name=0)
    datacve = pd.read_excel('FinalCVEsCWEs.xlsx', sheet_name=0)
    dataattack['Related Weaknesses'] = dataattack['Related Weaknesses'].astype(str).str.rstrip('.0')
    dataattack['Related Weaknesses'] = dataattack['Related Weaknesses'].apply(lambda x: 'CWE-' + str(x))
    dfAttackcapecMerged = pd.merge(datacve, dataattack, left_on='CWE-ID', right_on='Related Weaknesses')
    dfAttackcapecMerged = dfAttackcapecMerged.sample(n=10000)

    print(dfAttackcapecMerged.head(10))
    # dfAttackcapecMerged.to_csv('dfAttackCVEbyCWEMerged.csv.gz', index=False, compression='gzip')
    dfAttackcapecMerged.head(100000).to_excel('output.xlsx', index=False)
    # dfAttackcapecMerged.to_excel('dfAttackCVEbyCWEMerged.xlsx', index=False)


# getAllCweRelated("CWE-191")
# getDescription("Denial of service to NT mail servers including Ipswitch, Mdaemon, and Exchange through a buffer overflow in the SMTP HELO command.")
# mapCapecAttack()

# mapAttackCAPEC()
# mapattackcapeccvebycwe()


def exportCvesFromCwes():
    
    import csv
    import re
    result_df = pd.DataFrame(columns=['CVE-ID','CWE-ID', 'CWE-Name', 'CWE-Weakness Abstraction', 'CWE-Status', 'CWE-Description', 'CWE-Extended Description', 'CWE-Related Weaknesses', 'CWE-Weakness Ordinalities', 'CWE-Applicable Platforms', 'CWE-Background Details', 'CWE-Alternate Terms', 'CWE-Modes Of Introduction', 'CWE-Exploitation Factors', 'CWE-Likelihood of Exploit', 'CWE-Common Consequences', 'CWE-Detection Methods', 'CWE-Potential Mitigations', 'CWE-Observed Examples', 'CWE-Functional Areas', 'CWE-Affected Resources', 'CWE-Taxonomy Mappings', 'CWE-Related Attack Patterns', 'CWE-Notes'])

    with open('Datasets/cwes.csv', 'r', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:

            # print(row)
            pattern = r'(?<=REFERENCE:)(CVE-\d{4}-\d+)(?=:DESCRIPTION:)'
            matches = re.findall(pattern, row[17])

            # print(matches)
            for cve in matches:
                result_df = pd.concat([result_df, pd.DataFrame({'CVE-ID':[cve],'CWE-ID': [row[0]], 'CWE-Name': [row[1]], 'CWE-Weakness Abstraction': [row[2]], 'CWE-Status': [row[3]], 'CWE-Description': [row[4]], 'CWE-Extended Description': [row[5]], 'CWE-Related Weaknesses': [row[6]], 'CWE-Weakness Ordinalities': [row[7]], 'CWE-Applicable Platforms': [row[8]], 'CWE-Background Details': [row[9]], 'CWE-Alternate Terms': [row[10]], 'CWE-Modes Of Introduction': [row[11]], 'CWE-Exploitation Factors': [row[12]], 'CWE-Likelihood of Exploit': [row[13]], 'CWE-Common Consequences': [row[14]], 'CWE-Detection Methods': [row[15]], 'CWE-Potential Mitigations': [row[16]], 'CWE-Observed Examples': [row[17]], 'CWE-Functional Areas': [row[18]], 'CWE-Affected Resources': [row[19]], 'CWE-Taxonomy Mappings': [row[20]], 'CWE-Related Attack Patterns': [row[21]], 'CWE-Notes': [row[22]] })], ignore_index=True)
    result_df.to_excel('CVEsCWEs.xlsx', index=False)

   



# exportCvesFromCwes()
# mapCapecFilter()
# mapAttackCAPEC()
# addCveInfoAfterExportCvefromCWE()

mapattackcapeccvebycwe()