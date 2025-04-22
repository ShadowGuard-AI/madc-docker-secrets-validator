import re
import os
import sys
import yaml
import json
import logging
import click
from jsonschema import validate, ValidationError
import glob

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define schema for policy validation
POLICY_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "description": {"type": "string"},
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "description": {"type": "string"},
                    "regex": {"type": "string"},
                    "severity": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": ["id", "description", "regex", "severity"],
            },
        },
    },
    "required": ["name", "description", "rules"],
}


def validate_policy(policy):
    """
    Validates a policy against the POLICY_SCHEMA.

    Args:
        policy (dict): The policy to validate.

    Returns:
        bool: True if the policy is valid, False otherwise.
    """
    try:
        validate(instance=policy, schema=POLICY_SCHEMA)
        return True
    except ValidationError as e:
        logging.error(f"Policy validation error: {e}")
        return False


def load_policy(policy_file):
    """
    Loads a policy from a YAML or JSON file.

    Args:
        policy_file (str): The path to the policy file.

    Returns:
        dict: The loaded policy as a dictionary, or None if loading fails.
    """
    try:
        with open(policy_file, "r") as f:
            if policy_file.endswith(".yaml") or policy_file.endswith(".yml"):
                policy = yaml.safe_load(f)
            elif policy_file.endswith(".json"):
                policy = json.load(f)
            else:
                logging.error("Unsupported policy file format.  Must be YAML or JSON.")
                return None

        if not validate_policy(policy):
            return None

        return policy
    except FileNotFoundError:
        logging.error(f"Policy file not found: {policy_file}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML policy file: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON policy file: {e}")
        return None
    except Exception as e:
        logging.error(f"Error loading policy file: {e}")
        return None


def scan_file(file_path, policy):
    """
    Scans a single file for secrets based on the provided policy.

    Args:
        file_path (str): The path to the file to scan.
        policy (dict): The policy containing the regex rules.
    """
    try:
        with open(file_path, "r") as f:
            content = f.read()

        for rule in policy["rules"]:
            matches = re.finditer(rule["regex"], content, re.MULTILINE)
            for match in matches:
                logging.warning(
                    f"[{rule['severity'].upper()}] {rule['id']}: {rule['description']} - File: {file_path}, Line: {content[:match.start()].count(os.linesep) + 1}, Match: {match.group(0)}"
                )
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")


def scan_directory(directory_path, policy):
    """
    Scans all files in a directory for secrets.

    Args:
        directory_path (str): The path to the directory to scan.
        policy (dict): The policy containing the regex rules.
    """
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path, policy)


@click.command()
@click.option(
    "--policy-file",
    "-p",
    required=True,
    help="Path to the policy file (YAML or JSON).",
    type=click.Path(exists=True, readable=True),
)
@click.option(
    "--target",
    "-t",
    required=True,
    help="Path to the file or directory to scan.",
    type=click.Path(exists=True, readable=True, file_okay=True, dir_okay=True),
)
@click.option(
    "--log-level",
    "-l",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    help="Set the logging level.",
)
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help="Recursively scan directories. If not specified directory will be scanned only on the first level.",
)
@click.version_option()
def main(policy_file, target, log_level, recursive):
    """
    madc-Docker-Secrets-Validator: Scans Dockerfiles and docker-compose.yml files for potential exposure of secrets.
    """
    logging.getLogger().setLevel(log_level)

    logging.info("Starting madc-Docker-Secrets-Validator...")

    # Load the policy
    policy = load_policy(policy_file)
    if not policy:
        logging.error("Failed to load policy. Exiting.")
        sys.exit(1)

    # Check if the target is a file or directory
    if os.path.isfile(target):
        scan_file(target, policy)
    elif os.path.isdir(target):
        if recursive:
            scan_directory(target, policy)
        else:
            # scan files within the first level of directory
            for file in os.listdir(target):
                file_path = os.path.join(target, file)
                if os.path.isfile(file_path):
                    scan_file(file_path, policy)
    else:
        logging.error(f"Invalid target: {target}")
        sys.exit(1)

    logging.info("Scanning complete.")


if __name__ == "__main__":
    main()


# Example Usage:
# To run the script: python madc_docker_secrets_validator.py --policy-file policy.yaml --target Dockerfile
# Create a policy.yaml file like this:
# name: "Example Policy"
# description: "Detects common secrets"
# rules:
#   - id: "hardcoded-password"
#     description: "Detects hardcoded password"
#     regex: "password = \"[^\"]*\""
#     severity: "high"
#   - id: "api-key"
#     description: "Detects API key"
#     regex: "API_KEY = \"[^\"]*\""
#     severity: "medium"

# Scan a directory recursively: python madc_docker_secrets_validator.py --policy-file policy.yaml --target ./my_project --recursive

# Scan with a specific log level: python madc_docker_secrets_validator.py --policy-file policy.yaml --target Dockerfile --log-level DEBUG