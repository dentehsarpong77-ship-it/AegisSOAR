import os
import openai

# Point OpenAI client to your local OmniRoute instance
openai.api_base = "http://localhost:20128/v1"
openai.api_key = "omniroute-local"

print("=== Interactive Gemini Chat via OmniRoute ===")
print("Type 'exit' or 'quit' to end the session.\n")

messages = [{"role": "system", "content": "You are a helpful assistant."}]

while True:
    try:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            break
        if not user_input.strip():
            continue
            
        messages.append({"role": "user", "content": user_input})
        
        response = openai.ChatCompletion.create(
            model="gemini-1.5-pro",
            messages=messages
        )
        
        reply = response.choices[0].message['content']
        print(f"\nGemini: {reply}\n")
        messages.append({"role": "assistant", "content": reply})
        
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"\nError: {e}\n")
