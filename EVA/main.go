//TODO
/* use REST API to create a simple web interface
create an HTML form that takes in a csv file location and a location of the code base
-
-
-
parse csv -> for eac vuln (
- find path to vulnerable file
- structure raw text of csv line and vulnerable file
- send to AI (POST to /api/generate)
)
parse JSON AI response into DB
-
-
- for each entry in db
- show 
*/
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	// Prepare the JSON body
	requestBody := map[string]interface{}{
		"model":  "qwen2.5-coder:0.5b",
		"prompt": "Ollama is 22 years old and is busy saving the world. Respond using JSON",
		"stream": false,
		"format": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"age":       map[string]string{"type": "integer"},
				"available": map[string]string{"type": "boolean"},
			},
			"required": []string{"age", "available"},
		},
	}

	// Convert the Go map to JSON
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	// Create a new POST request
	url := "http://localhost:11434/api/generate"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}

	// Set the request header
	req.Header.Set("Content-Type", "application/json")

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	// Print the response status code and body
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Body: %s\n", string(respBody))
}
