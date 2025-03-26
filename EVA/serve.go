package main

import (
    "fmt"
    "html/template"
    "log"
    "net/http"

    _ "github.com/lib/pq"
)

func main() {
    http.HandleFunc("/", serveVulnerabilities)

    fmt.Println("Server started on http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func serveVulnerabilities(w http.ResponseWriter, r *http.Request) {
	db := conn_psql()

	// Query all vulnerabilities
	rows, err := db.Query("SELECT * FROM vulnerabilities")
	if err != nil {
		http.Error(w, "Error fetching data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var vulnerabilities []Vulnerability
	// Loop through each row and map columns to the struct
	for rows.Next() {
		var v Vulnerability

		// Explicitly map database columns to struct fields
		err := rows.Scan(
			&v.ID,                   // Column: id
			&v.Color,                // Column: color
			&v.Confirmed,            // Column: confirmed
			&v.FileContents,         // Column: file_contents
			&v.Filename,             // Column: filename
			&v.LOC,                  // Column: loc
			&v.LineNumber,           // Column: line_number
			&v.SeverityDescription,  // Column: severity_description
			&v.SeverityNumber,       // Column: severity_number
			&v.VulnDescription,     // Column: vuln_description
			&v.Vulnerability,        // Column: vulnerability
			&v.Reason,               // Column: reason
			&v.Verification,         // Column: verification
			&v.CreatedAt,            // Column: created_at
		)
		if err != nil {
			http.Error(w, "Error reading data", http.StatusInternalServerError)
			return
		}

		// Append to vulnerabilities slice
		vulnerabilities = append(vulnerabilities, v)
	}

	// Load HTML template
	tmpl := `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Vulnerabilities</title>
		<style>
			body { font-family: Arial, sans-serif; margin: 20px; }
			table { width: 100%; border-collapse: collapse; margin-top: 20px; }
			th, td { border: 1px solid black; padding: 10px; text-align: left; }
			th { background-color: #f2f2f2; }
			.confirmed { background-color: #d4edda; } /* Green for confirmed */
			.not-confirmed { background-color: #f8d7da; } /* Red for not confirmed */
		</style>
	</head>
	<body>
		<h2>Vulnerabilities List</h2>
		<table>
			<tr>
				<th>Color</th>
				<th>Confirmed</th>
				<th>File Contents</th>
				<th>Filename</th>
				<th>LOC</th>
				<th>Line Number</th>
				<th>Severity Description</th>
				<th>Severity Number</th>
				<th>Vulnerability</th>
				<th>Vuln Description</th>
				<th>Reason</th>
				<th>Verification</th>
			</tr>
			{{range .}}
			<tr>
				<td style="color: {{.Color}};">{{.Color}}</td>
				<td>{{.Confirmed}}</td>
				<td><pre>{{.FileContents}}</pre></td>
				<td>{{.Filename}}</td>
				<td>{{.LOC}}</td>
				<td>{{.LineNumber}}</td>
				<td>{{.SeverityDescription}}</td>
				<td>{{.SeverityNumber}}</td>
				<td>{{.Vulnerability}}</td>
				<td>{{.VulnDescription}}</td>
				<td>{{.Reason}}</td>
				<td>{{.Verification}}</td>
			</tr>
			{{end}}
		</table>
	</body>
	</html>
	`

	t, err := template.New("webpage").Parse(tmpl)
	if err != nil {
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}


    // Render template with vulnerabilities data
    t.Execute(w, vulnerabilities)
}
