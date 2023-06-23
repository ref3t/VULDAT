import pandas as pd
import re
from gensim.parsing.preprocessing import preprocess_documents
from sklearn.metrics.pairwise import cosine_similarity
from openpyxl import Workbook
import xlsxwriter

from sklearn.feature_extraction.text import TfidfVectorizer

def removeUrls (text):
    text = re.sub(r'(https|http)?:\/\/(\w|\.|\/|\?|\=|\&|\%)*\b', '', text, flags=re.MULTILINE)
    text = re.sub(r'\b\w*\d+\w*\b', '', text, flags=re.MULTILINE)
    return(text)
def removeURLsFromData(texts):
    return [removeUrls(text) for text in texts]

def testProcedureDescription():

    dfProcedures = pd.read_excel('app/datasets/attack-data.xlsx', sheet_name=3)

    dfProceduresCut = dfProcedures.loc[:, ['source ID', 'source name', 'mapping description']]
    
    dfProceduresCut['ID'] = dfProceduresCut['source ID']
    dfProceduresCut['description'] = dfProceduresCut['mapping description']
    dfProceduresCut['name'] = dfProceduresCut['source name']
    dfProceduresCut = dfProceduresCut.loc[:, ['ID', 'name','description']]
    
    trainAndTestSet = dfProceduresCut

    text_corpus = trainAndTestSet['description'].values
    text_corpus = removeURLsFromData(text_corpus)
    #############################################################################
    processed_corpus = preprocess_documents(text_corpus)
    list = []
    for item in processed_corpus:
        text = ' '.join(item)
        list.append(text.strip())
    trainAndTestSet['description'] = list

    org_description = trainAndTestSet.values
    random_rows = trainAndTestSet.sample(n=100)

    result = pd.DataFrame()
    result['ID'] = ''
    result['name'] = ''
    result['description'] = ''
    result['ID2'] = ''
    result['name2'] = ''
    result['description2'] = ''
    result['smilarityTFIDF'] = ''
    
    print (result)
    count = 0 
    for index, random in random_rows.iterrows():
        # print(random['descriptionTechniques'])
        # print(org_random_description[index][3])
        # # print(org_random_description[index])
        # input_string = random['description'] # 
        input_string = random['description']
        # input_string = random['description']+" " +random['descriptionTechniques']
        # input_string = ' '.join([random['description'],random['descriptionTechniques']])

        input_string = removeUrls(input_string)
        processed_corpus_input = preprocess_documents([input_string])
        
        list_input = []
        for item in processed_corpus_input:
            text = ' '.join(item)
            list_input.append(text.strip())
        vectorizer = TfidfVectorizer(use_idf=True)
        vectors = vectorizer.fit_transform(trainAndTestSet['description'])
        input_tfidf = vectorizer.transform(list_input)
        similarity_scores = cosine_similarity(input_tfidf, vectors)
        # find the index of the closest string
        closest_index = similarity_scores.argmax()
        closest_string = org_description[closest_index]
        closest_paragraph_indices = similarity_scores.argsort()[0][-1:]
        closest_paragraph_probabilities = [similarity_scores[0][index] for index in closest_paragraph_indices]
        for index2, probability in zip(closest_paragraph_indices, closest_paragraph_probabilities):
            new_row = {'ID': random['ID'],'name' : random['name'] ,'description' : random['description'],'ID2' : closest_string[0],'name2' : closest_string[1],'description2' : closest_string[2], 'smilarityTFIDF':f"{float(probability)*100:.2f}"}
            # Specify the index for the new row
            # Specify the index for the new row
            new_index = len(result)

            # Append the new row to the DataFrame using loc
            result.loc[new_index] = new_row
            # result.loc[count]['ID'] = random['ID']
            # result.loc[count]['name'] = random['name']
            # result.loc[count]['description'] = random['description']
            # result.loc[count]['ID2'] = closest_string[0]
            # result.loc[count]['name2'] = closest_string[1]
            # result.loc[count]['description2'] = closest_string[2]
            count = count + 1
            # print (result)
            # print(f"{closest_string[0]}###{closest_string[1]}####{closest_string[2]}###{float(probability)*100:.2f}")
    result.to_excel('testAttackProcedure.xlsx', index=False)




def read_cve_file():
    dataCve = pd.read_excel('app/datasets/Vulnerability_Dataset.xlsx', sheet_name=0)
    
    dataCve = dataCve.loc[:, ['CVE-ID', 'DESCRIPTION']]
    
    return dataCve
    
def splitTechniqueName(text):
    return text.split(':')[0]

def testAttackCve():   
    # Create a new Excel workbook
    workbook = xlsxwriter.Workbook('Dataset_TTP_CVE_Using_TFIDF_Proc_description.xlsx')
    
    # Add a new worksheet
    worksheet = workbook.add_worksheet()
    dfTactics = pd.read_excel('app/datasets/attack-data.xlsx', sheet_name=0)
    dfTechniques = pd.read_excel('app/datasets/attack-data.xlsx', sheet_name=2)
    dfProcedures = pd.read_excel('app/datasets/attack-data.xlsx', sheet_name=3)

    dfTacticsCut = dfTactics.loc[:, ['ID', 'name', 'description']]
    dfTacticsCut['type'] = 'tactics'
   
    dfTechniquesCut = dfTechniques.loc[:, ['ID', 'name', 'description']]
    dfTechniquesCut['type'] = 'techniques'

    dfTechniqueProcedureMerged = pd.merge(dfTechniques, dfProcedures, left_on='ID', right_on='target ID')

    dfProceduresCut = dfTechniqueProcedureMerged.loc[:, ['source ID', 'name','description', 'mapping description']]
    
    dfProceduresCut['ID'] = dfProceduresCut['source ID']
    dfProceduresCut['descriptionTechniques'] = dfProceduresCut['description']
    dfProceduresCut['description'] = dfProceduresCut['mapping description']
    dfProceduresCut['type'] = 'example'
    dfProceduresCut = dfProceduresCut.loc[:, ['ID', 'name', 'descriptionTechniques','description', 'type']]

    dataframe = pd.concat([dfTacticsCut, dfTechniquesCut, dfProceduresCut], ignore_index=True)
    
    trainAndTestSet = dataframe.loc[dataframe['type'] == 'example']
    trainAndTestSet['name'] = trainAndTestSet['name'].apply(splitTechniqueName) 
    
    dataframe2 = pd.concat([trainAndTestSet], ignore_index=True)
    test = dataframe2.loc[:, ['ID', 'name', 'descriptionTechniques','description', 'type']]
    trainAndTestSet = test
    org_TTP_description = trainAndTestSet.values
    #############################################################################
    text_corpus = trainAndTestSet['descriptionTechniques'].values
    text_corpus = removeURLsFromData(text_corpus)
    
    processed_corpus = preprocess_documents(text_corpus)
    list = []
    for item in processed_corpus:
        text = ' '.join(item)
        list.append(text.strip())
    trainAndTestSet['descriptionTechniques'] = list

    #############################################################################
    # text_corpus = trainAndTestSet['description'].values
    # text_corpus = removeURLsFromData(text_corpus)
    
    # processed_corpus = preprocess_documents(text_corpus)
    # list = []
    # for item in processed_corpus:
    #     text = ' '.join(item)
    #     list.append(text.strip())
    # trainAndTestSet['description'] = list

    dataframecve = read_cve_file()
    org_description = dataframecve.values
    text_corpus_input = dataframecve['DESCRIPTION'].values
    text_corpus_input = removeURLsFromData(text_corpus_input)
    #############################################################################
    processed_corpus_input = preprocess_documents(text_corpus_input)

    list_input = []
    for item in processed_corpus_input:
        text = ' '.join(item)
        list_input.append(text.strip())
    dataframecve['DESCRIPTION'] = list_input
    # org_description = dataframecve.values
    #add to file
    worksheet.write('A1', 'CVE_Num')
    worksheet.write('B1', 'CVE_Description')
    worksheet.write('C1', 'ProcedureID')
    worksheet.write('D1', 'ProcedureName')
    worksheet.write('E1', 'TechniquesDescription')
    worksheet.write('F1', 'ProcedureDescription')
    worksheet.write('G1', 'Probability')
    count = 2
    # for  ttp in zip(trainAndTestSet):
    dframe = pd.DataFrame(columns=['Column1', 'Column2'])
    trainAndTestSet = trainAndTestSet.sample(n=100)
    for index, ttp in trainAndTestSet.iterrows():
        # print(ttp['descriptionTechniques'])
        # print(org_TTP_description[index][3])
        # # print(org_TTP_description[index])
        input_string = ttp['descriptionTechniques'] 
        # input_string = ttp['descriptionTechniques']
        input_string = ttp['description']+" " +ttp['descriptionTechniques']
        # input_string = ' '.join([ttp['description'],ttp['descriptionTechniques']])

        input_string = removeUrls(input_string)
        processed_corpus_input = preprocess_documents([input_string])
        
        list_input = []
        for item in processed_corpus_input:
            text = ' '.join(item)
            list_input.append(text.strip())
        vectorizer = TfidfVectorizer(use_idf=True)
        vectors = vectorizer.fit_transform(dataframecve['DESCRIPTION'])
        input_tfidf = vectorizer.transform(list_input)
        similarity_scores = cosine_similarity(input_tfidf, vectors)
        # find the index of the closest string
        closest_index = similarity_scores.argmax()
        closest_paragraph_index = similarity_scores.argsort()[0][-2]
        max_similarity_procedure = similarity_scores.max()
        # get the closest string from the list
        closest_string = org_description[closest_index]
        # if max_similarity > 0.70:
        #     if i > 4:
        #         break
        #     i =  i+1 
        # print(closest_string)
        # Find the 10 closest paragraphs based on the cosine similarity scores
        # closest_paragraph_indices = similarity_scores.argsort()[0][-10:]
        closest_paragraph_indices = similarity_scores.argsort()[0][-10:]
        closest_paragraph_probabilities = [similarity_scores[0][index] for index in closest_paragraph_indices]
        for index2, probability in zip(closest_paragraph_indices, closest_paragraph_probabilities):
            # if probability > .50:
            # print("Paragraph Index:", index2)
            # print("Similarity Probability:", probability)
            # print("Paragraph Text:", org_description[index2])
            # print("---------------------------")
            # print(list_input)
            # print(org_description[index2][0])
            # print (ttp['name'])
            worksheet.write(f'A{count}', org_description[index2][0])
            worksheet.write(f'B{count}', org_description[index2][1])
            # worksheet.write(f'C{count}', org_TTP_description[index][0])
            # worksheet.write(f'D{count}',org_TTP_description[index][1])
            # worksheet.write(f'E{count}',org_TTP_description[index][2])
            # worksheet.write(f'F{count}',org_TTP_description[index][3])
            # worksheet.write(f'G{count}',(float(probability)*100))
            
            # worksheet.write(f'A{count}', closest_string[0])
            # worksheet.write(f'B{count}', closest_string[1])
            worksheet.write(f'C{count}', ttp['ID'])
            worksheet.write(f'D{count}',ttp['name'])
            worksheet.write(f'E{count}',ttp['descriptionTechniques'])
            worksheet.write(f'F{count}',ttp['description'])
            worksheet.write(f'G{count}',(float(probability)*100))
            count = count +1
            # print(f"{closest_string[0]}###{closest_string[1]}###{ttp['ID']}###{ttp['name']}###{ttp['descriptionTechniques']}###{ttp['description']}###{float(probability)*100:.2f}\n")
        
    workbook.close()
    printValuesMapping()

def CveDescriptionSpecefic(newdes):   
    
    dataframecve = read_cve_file()
    org_description = dataframecve.values
    text_corpus_input = dataframecve['DESCRIPTION'].values
    text_corpus_input = removeURLsFromData(text_corpus_input)
    #############################################################################
    processed_corpus_input = preprocess_documents(text_corpus_input)

    list_input = []
    for item in processed_corpus_input:
        text = ' '.join(item)
        list_input.append(text.strip())
    dataframecve['DESCRIPTION'] = list_input    
    input_string = newdes
    input_string = removeUrls(input_string)
    processed_corpus_input = preprocess_documents([input_string])
    list_input = []
    for item in processed_corpus_input:
        text = ' '.join(item)
        list_input.append(text.strip())
    vectorizer = TfidfVectorizer(use_idf=True)
    vectors = vectorizer.fit_transform(dataframecve['DESCRIPTION'])
    input_tfidf = vectorizer.transform(list_input)
    similarity_scores = cosine_similarity(input_tfidf, vectors)
    # find the index of the closest string
    closest_index = similarity_scores.argmax()
    closest_paragraph_index = similarity_scores.argsort()[0][-2]
    max_similarity_procedure = similarity_scores.max()
    # get the closest string from the list
    closest_string = org_description[closest_index]
    closest_paragraph_indices = similarity_scores.argsort()[0][-10:]
    closest_paragraph_probabilities = [similarity_scores[0][index] for index in closest_paragraph_indices]
    for index2, probability in zip(closest_paragraph_indices, closest_paragraph_probabilities):
        print(org_description[index2][0] + "  sim:"+str(float(probability)*100))
        


def print_rows_matching_values(dataframe, procID, techName,cves, values_procedureId,values_techName,cves_values ):
    # matching_rows = dataframe[ dataframe['CVE-ID'].isin(cves_values) & dataframe['ID_x'].isin(values_procedureId) & dataframe[techName].isin(values_techName) ]  
    # matching_rows = matching_rows[matching_rows[techName].isin(values_techName)]
    # condition1 = dataframe['CVE-ID'].apply(lambda x: cves_values[x] == desired_value1)
    # matching_rows = dataframe[ condition1]
    matching_rows = dataframe[dataframe[procID].isin(values_procedureId)]
    # matching_rows = matching_rows[matching_rows[techName].isin(values_techName)]
    matching_rows = matching_rows[matching_rows[cves].isin(cves_values)]
    # matching_rows.to_excel('test100Tech.xlsx', index=False)
    new_rows = []
    for ind in range(len(cves)):
        for index, row in matching_rows.iterrows():
            if row[1] == cves_values[ind] and row[8] == values_procedureId[ind]:
                new_rows.append(row)
                print(row[1])
    df = pd.DataFrame(new_rows)
    df.to_excel('test100Tech.xlsx', index=False)
           

def printValuesMapping():
    # dfProcedures = pd.read_excel('dfAttackCVEbyCWEMerged.csv/dfAttackCVEbyCWEMerged.xlsx', sheet_name=3)
    
    dfProcedures = pd.read_excel('Dataset_TTP_CVE_Using_TFIDF_Proc_description.xlsx')
    values_procedureId = []
    values_techName = []
    CV_Values = []

    for index,item in dfProcedures.iterrows():
        values_techName.append(item[3])
        values_procedureId.append(item[2])
        CV_Values.append(item[0])
    dfProcedures = pd.read_csv('dfAttackCVEMerged/dfAttackCVEbyCWEMerged3.csv')

    print_rows_matching_values(dfProcedures, 'ID_x','name','CVE-ID',values_procedureId, values_techName, CV_Values)
# testProcedureDescription()

#this just to make sure when we took 100 sample we have a good results from description of ttp with CVE
CveDescriptionSpecefic("Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: Establish Accounts or Compromise Accounts) and/or sending multiple, seemingly urgent messages. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services.[1] These services are more likely to have a less-strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries may create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and information about their environment. Adversaries may also use information from previous reconnaissance efforts (ex: Social Media or Search Victim-Owned Websites) to craft persuasive and believable lures.")  

