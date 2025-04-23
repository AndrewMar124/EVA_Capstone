# EVA: Enhanced Vulnerability Analysis

EVA is an easy and effective AI integration with Static Code Analysis. Built using Go, pSQL, and Ollama.

## Features

- Import CSV files from Visual Code Grepper (FOSS SCA tool)
- Run AI powered analysis on vulnerabiites
- Manage multiple projects and organize vulnerabilites

## Dependencies

Ensure the following dependencies are installed on your system:

- [PostgreSQL (pSQL)](https://www.postgresql.org/download/) *** Must be initialized with code in /EVA/misc/dbinit.txt, can be quickly run with start_psql.sh
- [Ollama](https://ollama.com/) *** Must download LLM within ollama
- *optional* [Go](https://golang.org/doc/install)
- *optional* [Visual Code Grepper](https://github.com/nccgroup/VCG)

## Installing LLM for local AI
- Install ollama
- Run following commands
```bash
ollama list
```
This command shows what models are currently installed.
```bash
ollama run qwen2.5-coder:0.5b
```
This downloads a model capable of runnning on a CPU only, if you have a GPU or better hardware consider running a 7B model.

## Running EVA
- Download the binary for your OS
- Or clone repo and run with GO
```bash
./EVA

OR navigate to EVA_CAPSTONE/EVA/

go run .
```
This will start the web server for EVA and if pSQL is set up will run the interface.

## UI Navigation
- On your browser navigate to http://localhost:8080/
- This is the Porject page where you can view different projcets within EVA
- Click "New Project" in the top navigation bar
- Insert a name and a csv file from EVA_CAPSTONE/VCG_Test_Results or from Visual Code Grepper
- Under Projects select your new project
- Click Run EVA
- Once EVA is complete (This may take some time depending on your system) you will see all of the vulnerabilitues and EVA analysis on the vuilnerability
- You can update and delete projects, delete, filter, or mark vulnerabilites as Confirmed
- Running EVA again in the same project will simply duplicate the entries.