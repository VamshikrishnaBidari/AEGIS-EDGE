import torch
from optimum.executorch import ExecuTorchModelForCausalLM
from transformers import AutoTokenizer

print("Loading offline quantized model... (this takes a few seconds)")
model_dir = "./llama32_1b_instruct"
model = ExecuTorchModelForCausalLM.from_pretrained(model_dir)
tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)

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