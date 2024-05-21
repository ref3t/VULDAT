# project_structure.py

from sentence_transformers import SentenceTransformer, losses, InputExample
from torch.utils.data import DataLoader
import pandas as pd
import torch

class DataLoaderCreator:
    def __init__(self, model_name):
        """
        Initialize the DataLoaderCreator class.

        Args:
        model_name (str): The name of the pretrained model.
        """
        self.model = SentenceTransformer(model_name)

    def create_training_dataset(self, df):
        """
        Create a training dataset from the provided DataFrame.

        Args:
        df (DataFrame): A DataFrame containing the data.

        Returns:
        DataLoader: A DataLoader instance containing the training data.
        """
        train_examples_cosine = []
        train_examples_dot = []
        grouped = df.groupby(['TechnqiueID'])

        for id, group in grouped:
            technique_description = group['TechnqiueDescription'].iloc[0]
            cve_descriptions = group['CVEDescription'].tolist()

            for cve_description in cve_descriptions:
                # Generate embeddings for the descriptions
                technique_embedding = self.model.encode(technique_description, convert_to_tensor=True)
                cve_embedding = self.model.encode(cve_description, convert_to_tensor=True)
                
                # Calculate the cosine similarity
                cosine_similarity = torch.nn.functional.cosine_similarity(technique_embedding.unsqueeze(0), cve_embedding.unsqueeze(0)).item()

                if cosine_similarity > 0.4:
                    # Add the example to the training data
                    train_examples_cosine.append({"sentences": [technique_description, cve_description], "score": cosine_similarity})

                # Normalize the embeddings
                technique_embedding = torch.nn.functional.normalize(technique_embedding.unsqueeze(0))
                cve_embedding = torch.nn.functional.normalize(cve_embedding.unsqueeze(0))

                # Calculate the dot product
                dot_product = torch.matmul(technique_embedding, cve_embedding.T).item()
                if dot_product > 0.4:
                    # Add the example to the training data
                    train_examples_dot.append({"sentences": [technique_description, cve_description], "score": dot_product})    
        # Convert the array to a DataFrame
        df = pd.DataFrame(train_examples_cosine)

        # Save the DataFrame to an Excel file
        df.to_excel('train_examples_cosine.xlsx', index=False, header=False)
        # Convert the array to a DataFrame
        df = pd.DataFrame(train_examples_dot)

        # Save the DataFrame to an Excel file
        df.to_excel('train_examples_dot.xlsx', index=False, header=False)



        # Convert the training data to InputExample instances
        train_data = [InputExample(texts=example["sentences"], label=example["score"]) for example in train_examples_cosine]

        # Convert the list of InputExamples to a DataLoader
        train_dataloader = DataLoader(train_data, shuffle=True, batch_size=16)

        return train_dataloader

class MyModel:
    def __init__(self, model_name):
        """
        Initialize the MyModel class.

        Args:
        model_name (str): The name of the pretrained model.
        """
        self.model = SentenceTransformer(model_name)
        self.data_loader_creator = DataLoaderCreator(model_name)

    def train_model(self, train_dataloader):
        """
        Train the model on the provided training data.

        Args:
        train_dataloader (DataLoader): A DataLoader instance containing the training data.
        """
        # Define the loss function
        train_loss = losses.ContrastiveLoss(model=self.model)

        # Train the model
        self.model.fit(train_objectives=[(train_dataloader, train_loss)], epochs=1, warmup_steps=100)

    def save_model(self, path):
        """
        Save the trained model to the specified path.

        Args:
        path (str): The path where the model should be saved.
        """
        # Save the model
        self.model.save(path)

    def load_model(self, path):
        """
        Load a trained model from the specified path.

        Args:
        path (str): The path where the model is saved.
        """
        # Load the model
        self.model = SentenceTransformer(path)

    def compute_similarity(self, sentence1, sentence2):
        """
        Compute the cosine similarity between the embeddings of two sentences.

        Args:
        sentence1 (str): The first sentence.
        sentence2 (str): The second sentence.

        Returns:
        float: The cosine similarity between the sentence embeddings.
        """
        # Generate embeddings for the sentences
        embedding1 = self.model.encode(sentence1, convert_to_tensor=True).unsqueeze(0)
        embedding2 = self.model.encode(sentence2, convert_to_tensor=True).unsqueeze(0)

        # Compute the cosine similarity between the embeddings
        cosine_similarity = torch.nn.functional.cosine_similarity(embedding1, embedding2)

        return cosine_similarity.item()

# Usage
if __name__ == "__main__":
    model = MyModel('multi-qa-mpnet-base-dot-v1')

    # Load your data from an Excel file
    df = pd.read_excel("./data/VULDATDataSetWithoutProcedures.xlsx")

    train_dataloader = model.data_loader_creator.create_training_dataset(df)
    model.train_model(train_dataloader)
    model.save_model("AttackModel")

    model.load_model("AttackModel")
    similarity = model.compute_similarity("ATTTACK 1", "ATTAACK 2")
    print("The cosine similarity between the attacks is:", similarity)
