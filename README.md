# <u>NVD APIs</u>
[Documentation](https://nvd.nist.gov/developers/vulnerabilities)

## CVE API
The CVE API is used to easily retrieve information on a single CVE or a collection of CVE from the NVD. The NVD contains
242,443 CVE records. Because of this, its APIs enforce offset-based pagination to answer requests for large collections.
Through a series of smaller “chunked” responses controlled by an offset startIndex and a page limit resultsPerPage users
may page through all the CVE in the NVD.

## Base URL
```bash
https://services.nvd.nist.gov/rest/json/cves/2.0
```

## Response schemas
- [CVE API Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
- [CVSSv3.1 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json)
- [CVSSv3.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.0.json)
- [CVSSv2.0 Schema](https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json)

## CVE Change History API
The CVE Change History API is used to easily retrieve information on changes made to a single CVE or a collection of CVE
from the NVD. This API provides additional transparency to the work of the NVD, allowing users to easily monitor when and
why vulnerabilities change.

The NVD has existed in some form since 1999 and the fidelity of this information has changed several times over the decades.
Earlier records may not contain the level of detail available with more recent CVE records. This is most apparent on CVE
records prior to 2015.

## Base URL
```bash
https://services.nvd.nist.gov/rest/json/cvehistory/2.0
```

## Response schema
```json
{
	"$schema": "http://json-schema.org/draft-07/schema#",
    "title": "JSON Schema for NVD CVE History API version 2.0",
	"$id": "https://csrc.nist.gov/schema/nvd/api/2.0/history_api_json_2.0.schema",
    "definitions": {
		"defChange": {
			"properties": {
				"change": {"$ref": "#/definitions/changeItem"}
			},
			"required": ["change"],
			"additionalProperties": false
		},
		
		"changeItem": {
			"properties": {
				"cveId": {
					"type": "string",
					"pattern": "^CVE-[0-9]{4}-[0-9]{4,}$"
				},
				"eventName": {"type": "string"},
				"cveChangeId": {"type": "string", "format": "uuid"},
				"sourceIdentifier": {"type": "string"},
				"created": {"type": "string", "format": "date-time"},
				"details": {
					"type": "array",
					"items": {"$ref": "#/definitions/detail"}
				}
			},
			"required": ["cveId", "eventName", "cveChangeId", "sourceIdentifier"],
			"additionalProperties": false
        },
		
		"detail": {
			"properties": {
				"action": {"type": "string"},
				"type": {"type": "string"},
				"oldValue": {"type": "string"},
				"newValue": {"type": "string"}
			},
			"required": ["type"],
			"additionalProperties": false
		}
	},
		
    "type": "object",
    "properties": {
		"resultsPerPage": {"type": "integer"},
		"startIndex": {"type": "integer"},
		"totalResults": {"type": "integer"},
		"format": {"type": "string"},
		"version": {"type": "string"},
		"timestamp": {"type": "string", "format": "date-time"},
        "cveChanges": {
            "description": "Array of CVE Changes",
            "type": "array",
            "items": {"$ref": "#/definitions/defChange"}
        }
    },
    "required": [
		"resultsPerPage",
		"startIndex",
		"totalResults",
		"format",
		"version",
		"timestamp"
    ]
}
```


## Setup
- Set up env variables
```bash
export MONGO_URI={uri}
```
```bash
export MONGO_DB={db}
```

- Create and run venv
```python
python3 -m venv {path to venv}
python3 bin/activate
```

- Run script
```python
python app.py
```
