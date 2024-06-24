# pdf_processing.py
import PyPDF2
import openai
import tiktoken

# Fonction pour compter les tokens
def count_tokens(messages, model="gpt-3.5-turbo"):
    encoding = tiktoken.encoding_for_model(model)
    num_tokens = 0
    for message in messages:
        num_tokens += len(encoding.encode(message["content"]))
    return num_tokens

# Fonction pour tronquer le texte
def truncate_text(text, max_tokens, model="gpt-3.5-turbo"):
    encoding = tiktoken.encoding_for_model(model)
    tokens = encoding.encode(text)
    if len(tokens) > max_tokens:
        tokens = tokens[:max_tokens]
    return encoding.decode(tokens)


def extract_text_from_pdf(pdf_path):
    with open(pdf_path, 'rb') as file:
        reader = PyPDF2.PdfReader(file)
        text = ''
        for page in reader.pages:
            text += page.extract_text() if page.extract_text() else ''
    return text

def generate_case_study(text):
    """Generate a structured case study from the given text using OpenAI."""
    try:
        # Structure des messages optimisés en français
        messages = [
            {"role": "user", "content": f"Résumé document : {text}"},
            {"role": "system", "content": "Étude de cas : Résumé, Problèmes, Solution, Ressources, Contraintes."}
        ]

        # Compter les tokens initiaux
        initial_tokens = count_tokens(messages)
        max_tokens = 16385

        # Vérifier si les messages dépassent la limite et tronquer si nécessaire
        if initial_tokens > max_tokens:
            remaining_tokens = max_tokens - count_tokens([messages[1]])
            truncated_text = truncate_text(text, remaining_tokens)
            messages[0]["content"] = f"Résumé du document : {truncated_text}"

        # Compter les tokens après la troncature
        final_tokens = count_tokens(messages)

        print(f"Tokens initiaux : {initial_tokens}")
        print(f"Tokens finaux : {final_tokens}")
        print(messages)

        # Appel API OpenAI pour générer l'étude de cas
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages
        )

        return response['choices'][0]['message']['content']
    except Exception as e:
        return f"Error in generating case study: {str(e)}"


def generate_quiz(text):
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "user", "content": f"""À partit de l'étude de cas donnée, générer un quiz sous format JavaScript en définissant une variable applée `MCQS`.
            `MCQS` est un tableau d'object contenant les clés suivantes (et rien d'autre):
                - 'question' (la qestion du quiz)
                - 'choice1' (le premier choix) 
                - 'choice2' (le deuxième choix) 
                - 'choice3' (le troisème choix)
                - 'choice4' (le quatrième choix)
                - 'answer' (le numéro de la bonne réponse)
                Les questions doivent être à propos de l'étude de cas suivante: {text}
            Vous devez donner exactement 10 questions.
            Vous devez répondre avec un program JavaScript valide (c'est à dire qu'avec du code)."""
            },
        ]
    )

    raw: str = response['choices'][0]['message']['content']
    raw = raw.replace("```javascript", "")
    raw = raw.replace("```", "")
    return raw
