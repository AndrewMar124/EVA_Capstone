#!/bin/bash

curl -X POST http://localhost:11434/api/generate \
     -H "Content-Type: application/json" \
     -d '{
         "model": "qwen2.5-coder:0.5b",
         "system": "You are an AI designed to analyze the results of a static code analysis. Your capabilities are limited to the following:\n1. You will receive an input: JSON with information from a static code analysis and the file contents of the vulnerable file.\n2. Your task is to analyze the JSON: You must verify the vulnerability by checking the associated code in FileContents.\nFor the vulnerability, you need to determine if it is a true positive (the vulnerability is present and valid) or a false positive (the vulnerability is not present or is incorrectly reported).\nRespond with the verification: either true or false positive and your reasoning in the provided JSON format.\n3. You are not allowed to perform any actions other than the above tasks. Specifically, you cannot:\n- Make changes to the codebase or file.\n- Report vulnerabilities not in the text file.\n4. Your responses should be clear, concise, and focused solely on indicating whether each vulnerability is a true positive or false positive.",
         "prompt": "'"$1"'",
         "format": {
             "type": "object",
             "properties": {
                 "Verification": {"type": "string"},
                 "Reason": {"type": "string"}
             },
             "required": ["Verification", "Reason"]
         },
         "stream": false,
         "options": {
             "top_k": 10,
             "top_p": 0.5,
             "repeat_last_n": 0,
             "temperature": 0.7
         }
     }' | jq '.response | fromjson | {Verification, Reason}'

