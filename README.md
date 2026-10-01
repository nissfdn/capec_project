# CAPEC Explorer

A Flask-based cybersecurity application developed to collect, process, store, and explore **MITRE CAPEC (Common Attack Pattern Enumeration and Classification)** data. The application downloads the CAPEC dataset, extracts and processes the CSV file, stores the data in a PostgreSQL database using Supabase, and provides a web interface for exploring attack patterns.

## Features

* Downloads the CAPEC dataset from MITRE
* Extracts and processes the downloaded ZIP and CSV files
* Processes CAPEC data using Pandas
* Stores structured data in a PostgreSQL database
* Uses Supabase for database management
* Provides a web interface for exploring CAPEC attack patterns
* Supports data parsing and processing with regular expressions

## Technologies

* Python
* Flask
* Jinja2
* Pandas
* Requests
* PostgreSQL
* Supabase
* Regular Expressions
* HTML/CSS
* Vercel

## Data Source

The project uses the **MITRE CAPEC** dataset.

[MITRE CAPEC Data](https://capec.mitre.org/data/downloads.html)
