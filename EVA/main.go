package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"log"
	"net/http"
	"strings"
	"syscall"
)

type Vulnerability struct {
	SeverityNumber      string `json:"Severity_Number"`
	SeverityDescription string `json:"Severity_Description"`
	Vulnerability       string `json:"Vulnerability"`
	VulnDescription     string `json:"Vuln_Description"`
	FileName            string `json:"FileName"`
	LineNumber          string `json:"LineNumber"`
	LOC                 string `json:"LOC"`
	Confirmed           string `json:"Confirmed"`
	Color               string `json:"Color"`
	FileContents        string `json:"FileContents"`
}

func jsonToHTMLTable(jsonData string) string {
	var records []map[string]interface{}

	// Attempt to unmarshal as an array
	err := json.Unmarshal([]byte(jsonData), &records)
	if err != nil {
		// If it fails, try to unmarshal as a single object
		var singleRecord map[string]interface{}
		if err := json.Unmarshal([]byte(jsonData), &singleRecord); err == nil {
			records = append(records, singleRecord) // Convert object to array
		} else {
			log.Printf("Error unmarshaling JSON: %v", err)
			return "<p>Error parsing JSON</p>"
		}
	}

	// If empty, return a message
	if len(records) == 0 {
		return "<p>No data available</p>"
	}

	// Extract headers from the first record
	var headers []string
	for key := range records[0] {
		headers = append(headers, key)
	}

	// Start HTML table
	var htmlTable strings.Builder
	htmlTable.WriteString("<table border='1'><tr>")

	// Add table headers
	for _, header := range headers {
		htmlTable.WriteString(fmt.Sprintf("<th>%s</th>", header))
	}
	htmlTable.WriteString("</tr>")

	// Add table rows
	for _, record := range records {
		htmlTable.WriteString("<tr>")
		for _, header := range headers {
			value := fmt.Sprintf("%v", record[header])
			htmlTable.WriteString(fmt.Sprintf("<td>%s</td>", value))
		}
		htmlTable.WriteString("</tr>")
	}

	// Close table
	htmlTable.WriteString("</table>")
	return htmlTable.String()
}



func getFileContents(filePath string) string {
	normalizedPath := strings.ReplaceAll(filePath, "\\", "/")
	path := strings.ReplaceAll(normalizedPath, "Z:", "")


	// Read file contents
	data, err := os.ReadFile(path)
	if err != nil {
		if pathErr, ok := err.(*os.PathError); ok {
			if errno, ok := pathErr.Err.(syscall.Errno); ok {
				fmt.Println("File system error:", errno)
			}
		}
		fmt.Println("Error reading file:", normalizedPath, err)
		return ""
	}

	return string(data)
}

func processCSVAndSendRequests(w http.ResponseWriter, r *http.Request) {
	// Open CSV file
	file, err := os.Open("/home/stud/EVA_Capstone/VCG_Test_Results/php_small.csv")
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

	// Define headers
	headers := []string{"Severity_Number", "Severity_Description", "Vulnerability", "Vuln_Description", "FileName", "LineNumber", "LOC", "Confirmed", "Color"}

	for _, row := range records[1:] {
		if len(row) != len(headers) {
			fmt.Println("Skipping malformed row:", row)
			continue
		}
		entry := make(map[string]string)
		for i, value := range row {
			entry[headers[i]] = value
		}

		// Read file contents
		fileContents := getFileContents(entry["FileName"])
		entry["FileContents"] = fileContents

		
		jsonEntry, err := json.Marshal(entry)
		if err != nil {
			fmt.Println("Error marshaling JSON:", err)
			continue
		}
		htmlTable := jsonToHTMLTable(string(jsonEntry))
		// Serve the HTML page
	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Vulnerability Report</title>
		<style>
			table { border-collapse: collapse; width: 100%%; }
			th, td { border: 1px solid black; padding: 8px; text-align: left; }
		</style>
	</head>
	<body>
		<h2>Vulnerabilities Report</h2>
		%s
	</body>
	</html>
`, htmlTable)
		// Send JSON to LLM
		response := sendToLLM(string(jsonEntry))
		//fmt.Println(string(jsonEntry))
		fmt.Println("AI Response:", response)
		
	}
}

func sendToLLM(prompt string) string {
	requestBody := map[string]interface{}{
		"model": "qwen2.5-coder:0.5b",
		"system": `You are an AI designed to analyze the results of a static code analysis. Your capabilities are limited to the following:

		1. You will receive an input:
			JSON with information from a static code analysis and the file contents of the vulnerable file.
	
		2. Your task is to analyze the JSON:
			You must verify the vulnerability by checking the associated code in FileContents.
			For the vulnerability, you need to determine if it is a true positive (the vulnerability is present and valid) or a false positive (the vulnerability is not present or is incorrectly reported).
			Respond with the verification: either true or false positive and your reasoning in the provided JSON fromat.
	
		3. You are not allowed to perform any actions other than the above tasks. Specifically, you cannot:
			Make changes to the codebase or file.
			Report Vulnerabilities not in the text file.
	
		4. Your responses should be clear, concise, and focused solely on indicating whether each vulnerability is a true positive or false positive.`,
		"prompt": prompt,
		"format": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"Verification": map[string]string{"type": "string"},
				"Reason": map[string]string{"type": "string"},
			},
			"required": []string{"Validation", "Reason"},
		},
		"stream": false,
		"options": map[string]interface{}{
			"top_k":         10,
			"top_p":         0.5,
			"repeat_last_n": 0,
			"temperature":   0.7,
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	req, err := http.NewRequest("POST", "http://localhost:11434/api/generate", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	var jsonResponse map[string]interface{}
	err = json.Unmarshal(respBody, &jsonResponse)
	if err != nil {
		log.Fatalf("Error unmarshaling response: %v", err)
	}

	if response, exists := jsonResponse["response"]; exists {
		return fmt.Sprintf("%v", response)
	}

	return "No response field found"
}

func main() {
	http.HandleFunc("/", processCSVAndSendRequests)
	fmt.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
