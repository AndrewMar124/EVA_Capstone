package main

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"

	_ "github.com/lib/pq"
)

type Vulnerability struct {
	ID int
	Color               string `json:"Color"`
	Confirmed           string `json:"Confirmed"`
	FileContents       string `json:"FileContents"`
	Filename           string `json:"FileName"`
	LOC                 string `json:"LOC"`
	LineNumber         string    `json:"LineNumber"`
	SeverityDescription string `json:"Severity_Description"`
	SeverityNumber     string    `json:"Severity_Number"`
	VulnDescription    string `json:"Vuln_Description"`
	Vulnerability      string `json:"Vulnerability"`
	Reason             string `json:"Reason"`
	Verification       string `json:"Verification"`
	Project_Name string
}

func conn_psql() *sql.DB{
	// Set up the connection string to PostgreSQL
	connStr := "user=postgres password=stud dbname=eva sslmode=disable"

	// Connect to the database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error opening connection to the database: ", err)
	}

	// Check if the connection is working
	err = db.Ping()
	if err != nil {
		log.Fatal("Error pinging the database: ", err)
	}
	return db
}

func insertVulnerabilityFromJSON(db *sql.DB, llmr string, prompt string, project string) error {

    // Debug log to ensure function is being reached
    fmt.Println(llmr)
	fmt.Println(prompt)

    // Parse JSON into Vulnerability struct
    var vuln Vulnerability
    err := json.Unmarshal([]byte(llmr), &vuln)
    if err != nil { return fmt.Errorf("failed to parse JSON: %v", err) }
	err2 := json.Unmarshal([]byte(prompt), &vuln)
    if err2 != nil { return fmt.Errorf("failed to parse JSON: %v", err) }

    // Log the parsed vulnerability for debugging
    fmt.Printf("Parsed vulnerability struct: %+v", vuln)

    query := `
        INSERT INTO vulnerability (
            confirmed, filename, loc, line_number,
            severity_description, vuln_description, vulnerability,
            reason, verification, project_name
        ) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id;
    `

    // Execute the query
    var id int
    err = db.QueryRow(query, vuln.Confirmed, vuln.Filename, vuln.LOC, vuln.LineNumber,
        vuln.SeverityDescription, vuln.VulnDescription, vuln.Vulnerability, vuln.Reason, vuln.Verification, project).
        Scan(&id)

    if err != nil {
        return fmt.Errorf("failed to insert vulnerability: %v", err)
    }

    return nil
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
		fmt.Println("Error reading file:", path, err)
		return ""
	}

	return string(data)
}

func processCSVAndSendRequests(file_path string, project string) {
	//db
	db := conn_psql()
	// Open CSV file
	file, err := os.Open(file_path)
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
	
		// Send JSON to LLM
		response := sendToLLM(string(jsonEntry))
		//fmt.Println(string(jsonEntry))
		//fmt.Println(response)

		// insert into psql db
		insertVulnerabilityFromJSON(db, string(jsonEntry), string(response), project)
		
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
			Respond with the verification: either true or false positive and your reasoning in the provided JSON fromat. Provide your resoning for this in Reason.
	
		3. You are not allowed to perform any actions other than the above tasks. Specifically, you cannot:
			Make changes to the codebase or file.
			Report Vulnerabilities not in the text file.
	
		4. Your responses should be clear, concise, and focused solely on indicating whether each vulnerability is a true positive or false positive.`,
		"prompt": prompt,
		"format": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"Reason": map[string]string{"type": "string"},
				"Verification": map[string]string{"type": "string"},
			},
			"required": []string{"Reason", "Verification"},
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

//func main() {
//	processCSVAndSendRequests()
//}
