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
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"log"
	"net/http"

)

type Vulnerability struct {
	SeverityNumber   int    `json:"severity_number"`
	SeverityDescription string `json:"severity_description"`
	Vulnerability    string `json:"vulnerability"`
	VulnDescription  string `json:"vuln_description"`
	FileName         string `json:"file_name"`
	LineNumber       int    `json:"line_number"`
	LOC              string `json:"line_of_code"`
	Confirmed        bool   `json:"confirmed"`
	Color            string `json:"color"`
}

func csv_reader() {
	// Open CSV file
	file, err := os.Open("/home/stud/EVA_Capstone/VCG_Test_Results/php_results.csv")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Read CSV file
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Allow variable number of fields per row
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading CSV:", err)
		return
	}

	if len(records) < 2 {
		fmt.Println("CSV does not contain enough data")
		return
	}

	// Extract headers
	headers := records[0]
	var jsonData []map[string]string

	// Convert CSV to JSON
	for _, row := range records[1:] {
		entry := make(map[string]string)
		for i, value := range row {
			if i < len(headers) {
				entry[headers[i]] = value
			}
		}
		jsonData = append(jsonData, entry)
	}

	// Convert to JSON format
	jsonOutput, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		fmt.Println("Error converting to JSON:", err)
		return
	}

	// Print JSON output
	fmt.Println(string(jsonOutput))
}



func main() {
	// Prepare the JSON body
	requestBody := map[string]interface{}{
		"model":  "qwen2.5-coder:0.5b",
		"system": `You are an AI designed to analyze the results of a static code analysis. Your capabilities are limited to the following:

    	1. You will receive two inputs:
        	A file location pointing to a file containing the results of a static code analysis.
        	A directory location pointing to the directory that contains the codebase that was analyzed.

    	2. Your task is to analyze the file containing the static code analysis results. For each vulnerability listed in the file:
        	You must verify the vulnerability by checking the associated code in the directory location.
        	For each vulnerability, you need to determine if it is a true positive (the vulnerability is present and valid) or a false positive (the vulnerability is not present or is incorrectly reported).

    	3. You are not allowed to perform any actions other than the above tasks. Specifically, you cannot:
        	Make changes to the codebase or file.
        	Process or analyze any information outside of the static code analysis results file and the provided directory.
        	Report Vulnerabilities not in the text file.

    	4. Your responses should be clear, concise, and focused solely on indicating whether each vulnerability is a true positive or false positive.
		`,
		"prompt": "Ollama is 22 years old and is busy saving the world. Respond using JSON",
  		"format": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"age":       map[string]string{"type": "integer"},
				"available": map[string]string{"type": "boolean"},
			},
			"required": []string{"age", "available"},
		},
		"stream": false,
		"options": map[string]interface{}{
			//
			"top_k":            10,
			//
			"top_p":            0.5,
			//
			"repeat_last_n":    0,
			//
			"temperature":      0.7,
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
// Parse the JSON response into a map
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(respBody, &jsonResponse)
	if err != nil {
		log.Fatalf("Error unmarshaling response: %v", err)
	}

	// Extract the "response" field
	if response, exists := jsonResponse["response"]; exists {
		// Print the response portion
		fmt.Printf("Response: %v\n", response)
	} else {
		log.Println("No 'response' field found in the JSON response.")
	}

	csv_reader()
}
