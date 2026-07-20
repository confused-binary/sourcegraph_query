# Sourcegraph AWS Service Frequency Tooling

A single script, `sg_query.py`, that fetches authoritative AWS resource type lists, queries public code frequency on [***Sourcegraph***](https://sourcegraph.com), and analyzes local data to measure how often AWS services appear in real-world Infrastructure-as-Code. The data answers the question: *when you find AWS credentials on an engagement, which services are actually worth checking first?*

Companion tooling for the "So... You Found AWS Access Keys" blog post.

## Requirements

- Python 3.8+
- `requests` library (`pip install requests`)
- A ***Sourcegraph*** access token (generate at https://sourcegraph.com/user/settings/tokens)

Set the token as an environment variable, never pass it as a CLI argument:

```
export SOURCEGRAPH_TOKEN=sgp_xxxxxxxxxxxx
```

## Usage

```
SOURCEGRAPH_TOKEN=sgp_xxx python sg_query.py
```

That's it. The script runs the full pipeline:

1. Fetches authoritative resource type lists from AWS CloudFormation spec and Terraform Registry
2. Fuzzy-matches CloudFormation resource types to Terraform equivalents (informs service grouping)
3. Queries ***Sourcegraph*** for per-service IaC frequency (Terraform `.tf` resources + CloudFormation `Type:` declarations)
4. Ranks services by resource type surface area
5. Merges everything into a single CSV

### Resuming after interruption

The script writes a tracking file (`sg_tracking.json`) as services complete. If interrupted, rerun the same command -- completed services are skipped automatically. Once all services finish, the tracking file is removed.

```
# interrupted mid-run
SOURCEGRAPH_TOKEN=sgp_xxx python sg_query.py

# just rerun -- picks up where it left off
SOURCEGRAPH_TOKEN=sgp_xxx python sg_query.py
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--output FILE` | `sg_results.csv` | Output CSV path |
| `--delay N` | `2.0` | Seconds between API calls (be polite to ***Sourcegraph***) |
| `--service SVC` | all | Restrict to specific service(s); repeatable |
| `--min-ratio FLOAT` | `0.50` | Lowest similarity threshold for CFN-to-TF mapping |
| `--endpoint URL` | ***Sourcegraph*** streaming API | Override the API endpoint |
| `--debug` | off | Enable debug logging |

### Examples

```
SOURCEGRAPH_TOKEN=sgp_xxx python sg_query.py --output results.csv

SOURCEGRAPH_TOKEN=sgp_xxx python sg_query.py --service ec2 --service s3

SOURCEGRAPH_TOKEN=sgp_xxx python sg_query.py --delay 3 --min-ratio 0.60
```

## Output

| File | Description |
|------|-------------|
| `sg_results.csv` | Merged per-service frequency + surface area data |
| `sg_results_map.csv` | Fuzzy-matched Terraform-to-CloudFormation resource mapping |

**CSV columns:** `service`, `tf_match_count`, `cfn_match_count`, `tf_repo_count`, `cfn_repo_count`, `tf_resource_count`, `cfn_resource_count`, `combined_resource_count`, `error`

## Caveats

- Terraform resources are attributed to AWS services via fuzzy matching against CloudFormation types. Resources without a CFN match fall back to their Terraform prefix as the service name.
- Each query targets a single file extension (`.tf`, `.yaml`, `.yml`, `.json`, `.jsn`) with `fork:no` to minimize shard pressure. If ***Sourcegraph*** still hits a shard limit on a narrow query, the count is reported with a `(shard limit -- count is a floor)` warning.
