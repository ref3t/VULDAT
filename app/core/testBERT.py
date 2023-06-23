from transformers import RobertaTokenizer, RobertaConfig, RobertaModel

# device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
tokenizer = RobertaTokenizer.from_pretrained("bert-base-uncased")
# model = RobertaModel.from_pretrained("microsoft/codebert-base")
# model.to(device)


text = 'Dell EMC NetWorker versions between 9.0 and 9.1.1.8 through 9.2.1.3, and the version 18.1.0.1 contain a Clear-Text authentication over network vulnerability in the Rabbit MQ Advanced Message Queuing Protocol (AMQP) component. User credentials are sent unencrypted to the remote AMQP service. An unauthenticated attacker in the same network collision domain, could potentially sniff the password from the network and use it to access the component using the privileges of the compromised user.'
token = tokenizer.tokenize(text)


print(token)