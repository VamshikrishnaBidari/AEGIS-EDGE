import torch
from optimum.executorch import ExecuTorchModelForCausalLM
from transformers import AutoTokenizer

print("Loading offline model... (this takes a few seconds)")
model = ExecuTorchModelForCausalLM.from_pretrained("./llama32_1b_instruct")
tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-3.2-1B-Instruct")

print("\nModel loaded! Type 'quit' to exit.")
print("-" * 40)

while True:
    user_input = input("\nYou: ")
    if user_input.lower() in ['quit', 'exit']:
        break
        
    prompt = tokenizer.apply_chat_template(
        [{"role": "user", "content": user_input}],
        tokenize=False, 
        add_generation_prompt=True,
    )
    
    print("Llama is thinking...")
    
    response = model.text_generation(tokenizer=tokenizer, prompt=prompt, max_seq_len=128)
    
    print(f"\nLlama: {response}")