package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

	_ "github.com/lib/pq"
)

type Project struct {
	Name string
	Sca string
}

func main() {
	http.HandleFunc("/", serveDash)
	http.HandleFunc("/vuln", serveVulnerabilities)
	http.HandleFunc("/proj", projectListHandler)
	http.HandleFunc("/create_proj", serve_create_proj)
	http.HandleFunc("/view_project", view_project)

	http.HandleFunc("/createProject", createProject)
	http.HandleFunc("/runEVA", runEVA)

	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	fmt.Println("Server started on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func serveDash(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "dash.html")
}

func serve_create_proj(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "create_project.html")
}

func view_project(w http.ResponseWriter, r *http.Request) {
	// Parse the `id` parameter from the URL
	var projects Project
	p := r.URL.Query().Get("p")
	projects.Name = p
	if projects.Name == "" {
		http.Error(w, "Missing 'p' parameter", http.StatusBadRequest)
		return
	}
	db := conn_psql()
	_ = db.QueryRow("SELECT sca FROM project WHERE name = $1", projects.Name).Scan(&projects.Sca)

	// Parse and execute template
	tmpl, err := template.ParseFiles("view_project.html")
	if err != nil {
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}

	// Render the template with project names
	tmpl.Execute(w, projects)

}

func runEVA(w http.ResponseWriter, r *http.Request) {
	// Parse the `id` parameter from the URL
	project := r.URL.Query().Get("p")
	if project == "" {
		http.Error(w, "Missing 'p' parameter", http.StatusBadRequest)
		return
	}

	db := conn_psql()
	var file_path string
	_ = db.QueryRow("SELECT sca FROM project WHERE name = $1", project).Scan(&file_path)
	

	// Call another function with the retrieved value
	processCSVAndSendRequests(file_path, project)

	// Respond to client
	fmt.Fprintf(w, "Processed value: %s", file_path)
}

func projectListHandler(w http.ResponseWriter, r *http.Request) {
	// Connect to the database
	db := conn_psql()
	defer db.Close()

	// Query all project names
	rows, err := db.Query("SELECT name FROM project")
	if err != nil {
		http.Error(w, "Failed to fetch projects", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Slice to store project names
	var projects []Project

	// Iterate over query results
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.Name); err != nil {
			http.Error(w, "Error scanning projects", http.StatusInternalServerError)
			return
		}
		projects = append(projects, p)
	}

	// Parse and execute template
	tmpl, err := template.ParseFiles("proj_select.html")
	if err != nil {
		http.Error(w, "Template parsing error", http.StatusInternalServerError)
		return
	}

	// Render the template with project names
	tmpl.Execute(w, projects)
}

func createProject(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    err := r.ParseMultipartForm(10 << 20)
    if err != nil {
        http.Error(w, "Unable to parse form", http.StatusBadRequest)
        return
    }

    projectName := r.FormValue("name")
    if projectName == "" {
        http.Error(w, "Project name is required", http.StatusBadRequest)
        return
    }

    file, handler, err := r.FormFile("file")
    if err != nil {
        http.Error(w, "Unable to get the file from the form", http.StatusBadRequest)
        return
    }
    defer file.Close()

    filePath := filepath.Join("uploads", handler.Filename)

    dst, err := os.Create(filePath)
    if err != nil {
        http.Error(w, "Unable to create the file", http.StatusInternalServerError)
        return
    }
    defer dst.Close()

    _, err = dst.ReadFrom(file)
    if err != nil {
        http.Error(w, "Unable to save the file", http.StatusInternalServerError)
        return
    }

    db := conn_psql()
    defer db.Close()

    query := "INSERT INTO project (name, sca) VALUES ($1, $2)"
    _, err = db.Exec(query, projectName, filePath)
    if err != nil {
        http.Error(w, "Failed to insert project into database", http.StatusInternalServerError)
        return
    }

	http.Redirect(w, r, r.Header.Get("/proj"), http.StatusSeeOther)
}


func serveVulnerabilities(w http.ResponseWriter, r *http.Request) {
	db := conn_psql()


	project := r.URL.Query().Get("p")
	if project == "" {
		http.Error(w, "Missing 'p' parameter", http.StatusBadRequest)
		return
	}

	// Query all vulnerabilities
	rows, err := db.Query("SELECT * FROM vulnerability WHERE project_name = $1", project)
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
			&v.ID,                  // Column: id
			&v.Color,               // Column: color
			&v.Confirmed,           // Column: confirmed
			&v.FileContents,        // Column: file_contents
			&v.Filename,            // Column: filename
			&v.LOC,                 // Column: loc
			&v.LineNumber,          // Column: line_number
			&v.SeverityDescription, // Column: severity_description
			&v.SeverityNumber,      // Column: severity_number
			&v.VulnDescription,     // Column: vuln_description
			&v.Vulnerability,       // Column: vulnerability
			&v.Reason,              // Column: reason
			&v.Verification,        // Column: verification
			&v.CreatedAt,           // Column: created_at
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
