#!/bin/bash

# Define the output file
output_file="Response.md"

# # Ensure the output file is empty or create it if it doesn't exist
# > "$output_file"


# Loop until the user decides to exit
while true; do
    # Prompt the user for input
    read -p "Enter something (or type 'exit' to quit): " user_input

    # Check if the user wants to exit
    if [[ "$user_input" == "exit" ]]; then
        echo "Exiting..."
        break
    fi

    # Print the variable
    echo -e "<h2>======  Start of $user_input  ======</h2>" >> "Response.md"

    # Run the command and append the output directly to the file
    ollama run EVA_demo "$user_input" >> "$output_file"
    
    echo -e "<h2>======  End of $user_input  ======</h2>" >> "Response.md"

    # Inform the user that the response has been saved
    echo "The response has been saved to $output_file"

done
