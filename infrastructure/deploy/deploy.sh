#!/bin/bash

IMAGE_URI=$1

# Leggi il file CloudFormation e l'ambiente
origFile=$( cat ./infrastructure/aws/cloudformation.yaml )
input_string=$(cat ./infrastructure/envs/dev.txt)
IFS="="

# Sostituisci le variabili nel file CloudFormation
while read -r chiave valore;
do
    valore=$(echo $valore | sed  "s/\//\\\\\//g")
    echo "Sostituzione: Chiave: $chiave, Valore: $valore"
    origFile=$( sed  "s/{{$chiave}}/$valore/g" <<< "$origFile" )
done <<< "$input_string"

# Scrivi il file finale con le sostituzioni effettuate
echo "$origFile" > ./infrastructure/aws/cfn.yaml
echo "------------------- DUMP CLOUDFORMATION -----------------"
cat ./infrastructure/aws/cfn.yaml

echo "------------------- CREAZIONE DEL CHANGE SET ----------------"

# Verifica se lo stack esiste già
stack_status=$(aws cloudformation describe-stacks --stack-name DDAIApiAuthorizer --query 'Stacks[0].StackStatus' --output text 2>/dev/null)

# Se lo stack non esiste, crealo con un change set
if [ $? -eq 0 ]; then
    echo "Lo stack esiste già con lo stato: $stack_status"
    action="UPDATE"
else
    echo "Lo stack non esiste, verrà creato."
    action="CREATE"
fi

# Crea un nome univoco per il change set
change_set_name="changeset-$(date +%Y%m%d%H%M%S)"

echo "IMAGE_URI: $IMAGE_URI"

# Crea il change set
aws cloudformation create-change-set \
    --stack-name DDAIApiAuthorizer \
    --template-body file://./infrastructure/aws/cfn.yaml \
    --parameters ParameterKey=EcrImageUri,ParameterValue=${IMAGE_URI} \
    --capabilities CAPABILITY_NAMED_IAM \
    --change-set-name $change_set_name \
    --change-set-type $action

# Attendi che il change set sia creato
echo "In attesa della creazione del change set..."
aws cloudformation wait change-set-create-complete --stack-name DDAIApiAuthorizer --change-set-name $change_set_name

if [ $? -ne 0 ]; then
    echo "Errore nella creazione del change set."
    exit 1
fi

echo "Change set creato con successo: $change_set_name"
echo "------------------- ESECUZIONE DEL CHANGE SET ----------------"

# Esegui il change set
aws cloudformation execute-change-set --stack-name DDAIApiAuthorizer --change-set-name $change_set_name

if [ $? -eq 0 ]; then
    echo "Change set eseguito con successo."
else
    echo "Errore nell'esecuzione del change set."
    exit 1
fi
