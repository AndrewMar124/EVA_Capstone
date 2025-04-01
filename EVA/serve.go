package main

import (
    "fmt"
    "html/template"
    "log"
    "net/http"

    _ "github.com/lib/pq"
)

func main() {
    http.HandleFunc("/", serveDash)
	http.HandleFunc("/vuln", serveVulnerabilities)

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

    fmt.Println("Server started on http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func serveDash(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "dash.html")
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
	tmpl, err := template.ParseFiles("vuln.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}

    // Render template with vulnerabilities data
    tmpl.Execute(w, vulnerabilities)
}
